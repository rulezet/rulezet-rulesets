rule TTP_XOR_QUAD_CurrentVersionRun_2d5b {
  strings:
    $key_2d5b = { 7e 34 [2] 5a 3a [2] 71 16 [2] 5f 34 [2] 4b 2f [2] 44 35 [2] 5a 28 [2] 58 29 [2] 43 2f [2] 5f 28 [2] 43 07 }

  condition:
    any of them
}