rule TTP_XOR_QUAD_CurrentVersionRun_0bb7 {
  strings:
    $key_0bb7 = { 58 d8 [2] 7c d6 [2] 57 fa [2] 79 d8 [2] 6d c3 [2] 62 d9 [2] 7c c4 [2] 7e c5 [2] 65 c3 [2] 79 c4 [2] 65 eb }

  condition:
    any of them
}