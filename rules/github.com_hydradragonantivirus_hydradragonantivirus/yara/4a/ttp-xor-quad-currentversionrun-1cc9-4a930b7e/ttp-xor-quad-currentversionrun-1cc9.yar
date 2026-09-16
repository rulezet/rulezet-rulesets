rule TTP_XOR_QUAD_CurrentVersionRun_1cc9 {
  strings:
    $key_1cc9 = { 4f a6 [2] 6b a8 [2] 40 84 [2] 6e a6 [2] 7a bd [2] 75 a7 [2] 6b ba [2] 69 bb [2] 72 bd [2] 6e ba [2] 72 95 }

  condition:
    any of them
}