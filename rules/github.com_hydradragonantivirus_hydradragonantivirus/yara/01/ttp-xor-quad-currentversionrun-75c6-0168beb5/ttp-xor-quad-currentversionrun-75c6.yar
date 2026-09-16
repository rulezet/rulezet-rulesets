rule TTP_XOR_QUAD_CurrentVersionRun_75c6 {
  strings:
    $key_75c6 = { 26 a9 [2] 02 a7 [2] 29 8b [2] 07 a9 [2] 13 b2 [2] 1c a8 [2] 02 b5 [2] 00 b4 [2] 1b b2 [2] 07 b5 [2] 1b 9a }

  condition:
    any of them
}