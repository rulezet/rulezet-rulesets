rule TTP_XOR_QUAD_CurrentVersionRun_f5d5 {
  strings:
    $key_f5d5 = { a6 ba [2] 82 b4 [2] a9 98 [2] 87 ba [2] 93 a1 [2] 9c bb [2] 82 a6 [2] 80 a7 [2] 9b a1 [2] 87 a6 [2] 9b 89 }

  condition:
    any of them
}