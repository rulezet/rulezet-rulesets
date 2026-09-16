rule TTP_XOR_QUAD_CurrentVersionRun_f3b7 {
  strings:
    $key_f3b7 = { a0 d8 [2] 84 d6 [2] af fa [2] 81 d8 [2] 95 c3 [2] 9a d9 [2] 84 c4 [2] 86 c5 [2] 9d c3 [2] 81 c4 [2] 9d eb }

  condition:
    any of them
}