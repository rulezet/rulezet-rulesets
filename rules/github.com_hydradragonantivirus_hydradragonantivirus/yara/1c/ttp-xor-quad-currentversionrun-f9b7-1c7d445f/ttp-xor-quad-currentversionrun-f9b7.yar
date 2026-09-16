rule TTP_XOR_QUAD_CurrentVersionRun_f9b7 {
  strings:
    $key_f9b7 = { aa d8 [2] 8e d6 [2] a5 fa [2] 8b d8 [2] 9f c3 [2] 90 d9 [2] 8e c4 [2] 8c c5 [2] 97 c3 [2] 8b c4 [2] 97 eb }

  condition:
    any of them
}