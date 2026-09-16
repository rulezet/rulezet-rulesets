rule TTP_XOR_QUAD_CurrentVersionRun_f2d6 {
  strings:
    $key_f2d6 = { a1 b9 [2] 85 b7 [2] ae 9b [2] 80 b9 [2] 94 a2 [2] 9b b8 [2] 85 a5 [2] 87 a4 [2] 9c a2 [2] 80 a5 [2] 9c 8a }

  condition:
    any of them
}