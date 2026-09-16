rule TTP_XOR_QUAD_CurrentVersionRun_f5c7 {
  strings:
    $key_f5c7 = { a6 a8 [2] 82 a6 [2] a9 8a [2] 87 a8 [2] 93 b3 [2] 9c a9 [2] 82 b4 [2] 80 b5 [2] 9b b3 [2] 87 b4 [2] 9b 9b }

  condition:
    any of them
}