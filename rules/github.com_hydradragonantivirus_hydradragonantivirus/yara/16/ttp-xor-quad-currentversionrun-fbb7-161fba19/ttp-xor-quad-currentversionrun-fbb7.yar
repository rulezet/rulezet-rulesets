rule TTP_XOR_QUAD_CurrentVersionRun_fbb7 {
  strings:
    $key_fbb7 = { a8 d8 [2] 8c d6 [2] a7 fa [2] 89 d8 [2] 9d c3 [2] 92 d9 [2] 8c c4 [2] 8e c5 [2] 95 c3 [2] 89 c4 [2] 95 eb }

  condition:
    any of them
}