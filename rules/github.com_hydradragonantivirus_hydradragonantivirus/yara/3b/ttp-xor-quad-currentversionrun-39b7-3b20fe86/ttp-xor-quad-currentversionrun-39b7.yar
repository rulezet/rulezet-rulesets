rule TTP_XOR_QUAD_CurrentVersionRun_39b7 {
  strings:
    $key_39b7 = { 6a d8 [2] 4e d6 [2] 65 fa [2] 4b d8 [2] 5f c3 [2] 50 d9 [2] 4e c4 [2] 4c c5 [2] 57 c3 [2] 4b c4 [2] 57 eb }

  condition:
    any of them
}