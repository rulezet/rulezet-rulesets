rule TTP_XOR_QUAD_CurrentVersionRun_f5b5 {
  strings:
    $key_f5b5 = { a6 da [2] 82 d4 [2] a9 f8 [2] 87 da [2] 93 c1 [2] 9c db [2] 82 c6 [2] 80 c7 [2] 9b c1 [2] 87 c6 [2] 9b e9 }

  condition:
    any of them
}