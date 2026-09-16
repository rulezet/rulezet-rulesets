rule TTP_XOR_QUAD_CurrentVersionRun_f2b7 {
  strings:
    $key_f2b7 = { a1 d8 [2] 85 d6 [2] ae fa [2] 80 d8 [2] 94 c3 [2] 9b d9 [2] 85 c4 [2] 87 c5 [2] 9c c3 [2] 80 c4 [2] 9c eb }

  condition:
    any of them
}