rule TTP_XOR_QUAD_CurrentVersionRun_75b7 {
  strings:
    $key_75b7 = { 26 d8 [2] 02 d6 [2] 29 fa [2] 07 d8 [2] 13 c3 [2] 1c d9 [2] 02 c4 [2] 00 c5 [2] 1b c3 [2] 07 c4 [2] 1b eb }

  condition:
    any of them
}