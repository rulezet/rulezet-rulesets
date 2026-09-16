rule TTP_XOR_QUAD_CurrentVersionRun_00c5 {
  strings:
    $key_00c5 = { 53 aa [2] 77 a4 [2] 5c 88 [2] 72 aa [2] 66 b1 [2] 69 ab [2] 77 b6 [2] 75 b7 [2] 6e b1 [2] 72 b6 [2] 6e 99 }

  condition:
    any of them
}