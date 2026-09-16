rule TTP_XOR_QUAD_CurrentVersionRun_19b7 {
  strings:
    $key_19b7 = { 4a d8 [2] 6e d6 [2] 45 fa [2] 6b d8 [2] 7f c3 [2] 70 d9 [2] 6e c4 [2] 6c c5 [2] 77 c3 [2] 6b c4 [2] 77 eb }

  condition:
    any of them
}