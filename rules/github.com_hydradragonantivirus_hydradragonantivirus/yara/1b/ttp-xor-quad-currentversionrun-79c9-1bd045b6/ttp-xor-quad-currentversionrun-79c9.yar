rule TTP_XOR_QUAD_CurrentVersionRun_79c9 {
  strings:
    $key_79c9 = { 2a a6 [2] 0e a8 [2] 25 84 [2] 0b a6 [2] 1f bd [2] 10 a7 [2] 0e ba [2] 0c bb [2] 17 bd [2] 0b ba [2] 17 95 }

  condition:
    any of them
}