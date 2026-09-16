rule TTP_XOR_QUAD_CurrentVersionRun_69b7 {
  strings:
    $key_69b7 = { 3a d8 [2] 1e d6 [2] 35 fa [2] 1b d8 [2] 0f c3 [2] 00 d9 [2] 1e c4 [2] 1c c5 [2] 07 c3 [2] 1b c4 [2] 07 eb }

  condition:
    any of them
}