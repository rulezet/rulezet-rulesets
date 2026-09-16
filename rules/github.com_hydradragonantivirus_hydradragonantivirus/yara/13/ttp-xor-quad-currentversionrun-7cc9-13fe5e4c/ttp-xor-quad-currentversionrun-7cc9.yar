rule TTP_XOR_QUAD_CurrentVersionRun_7cc9 {
  strings:
    $key_7cc9 = { 2f a6 [2] 0b a8 [2] 20 84 [2] 0e a6 [2] 1a bd [2] 15 a7 [2] 0b ba [2] 09 bb [2] 12 bd [2] 0e ba [2] 12 95 }

  condition:
    any of them
}