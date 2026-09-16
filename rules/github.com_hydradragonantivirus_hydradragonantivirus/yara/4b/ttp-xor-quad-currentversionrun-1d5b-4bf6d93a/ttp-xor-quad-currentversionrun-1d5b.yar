rule TTP_XOR_QUAD_CurrentVersionRun_1d5b {
  strings:
    $key_1d5b = { 4e 34 [2] 6a 3a [2] 41 16 [2] 6f 34 [2] 7b 2f [2] 74 35 [2] 6a 28 [2] 68 29 [2] 73 2f [2] 6f 28 [2] 73 07 }

  condition:
    any of them
}