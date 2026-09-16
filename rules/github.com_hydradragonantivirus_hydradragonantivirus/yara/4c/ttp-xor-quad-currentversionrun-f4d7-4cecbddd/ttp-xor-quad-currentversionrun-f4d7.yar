rule TTP_XOR_QUAD_CurrentVersionRun_f4d7 {
  strings:
    $key_f4d7 = { a7 b8 [2] 83 b6 [2] a8 9a [2] 86 b8 [2] 92 a3 [2] 9d b9 [2] 83 a4 [2] 81 a5 [2] 9a a3 [2] 86 a4 [2] 9a 8b }

  condition:
    any of them
}