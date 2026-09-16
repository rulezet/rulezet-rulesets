rule TTP_XOR_QUAD_CurrentVersionRun_7db7 {
  strings:
    $key_7db7 = { 2e d8 [2] 0a d6 [2] 21 fa [2] 0f d8 [2] 1b c3 [2] 14 d9 [2] 0a c4 [2] 08 c5 [2] 13 c3 [2] 0f c4 [2] 13 eb }

  condition:
    any of them
}