rule TTP_XOR_QUAD_CurrentVersionRun_f4d5 {
  strings:
    $key_f4d5 = { a7 ba [2] 83 b4 [2] a8 98 [2] 86 ba [2] 92 a1 [2] 9d bb [2] 83 a6 [2] 81 a7 [2] 9a a1 [2] 86 a6 [2] 9a 89 }

  condition:
    any of them
}