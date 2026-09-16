rule TTP_XOR_QUAD_CurrentVersionRun_75c7 {
  strings:
    $key_75c7 = { 26 a8 [2] 02 a6 [2] 29 8a [2] 07 a8 [2] 13 b3 [2] 1c a9 [2] 02 b4 [2] 00 b5 [2] 1b b3 [2] 07 b4 [2] 1b 9b }

  condition:
    any of them
}