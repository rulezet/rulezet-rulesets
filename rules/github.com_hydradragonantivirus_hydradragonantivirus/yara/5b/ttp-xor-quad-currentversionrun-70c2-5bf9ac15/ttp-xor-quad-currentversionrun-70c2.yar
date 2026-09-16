rule TTP_XOR_QUAD_CurrentVersionRun_70c2 {
  strings:
    $key_70c2 = { 23 ad [2] 07 a3 [2] 2c 8f [2] 02 ad [2] 16 b6 [2] 19 ac [2] 07 b1 [2] 05 b0 [2] 1e b6 [2] 02 b1 [2] 1e 9e }

  condition:
    any of them
}