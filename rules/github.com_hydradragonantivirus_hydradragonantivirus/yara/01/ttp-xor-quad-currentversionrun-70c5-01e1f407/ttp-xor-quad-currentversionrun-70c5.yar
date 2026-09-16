rule TTP_XOR_QUAD_CurrentVersionRun_70c5 {
  strings:
    $key_70c5 = { 23 aa [2] 07 a4 [2] 2c 88 [2] 02 aa [2] 16 b1 [2] 19 ab [2] 07 b6 [2] 05 b7 [2] 1e b1 [2] 02 b6 [2] 1e 99 }

  condition:
    any of them
}