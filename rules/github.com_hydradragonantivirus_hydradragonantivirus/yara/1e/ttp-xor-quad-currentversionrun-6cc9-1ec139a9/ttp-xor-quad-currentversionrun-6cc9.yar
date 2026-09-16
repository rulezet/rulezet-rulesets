rule TTP_XOR_QUAD_CurrentVersionRun_6cc9 {
  strings:
    $key_6cc9 = { 3f a6 [2] 1b a8 [2] 30 84 [2] 1e a6 [2] 0a bd [2] 05 a7 [2] 1b ba [2] 19 bb [2] 02 bd [2] 1e ba [2] 02 95 }

  condition:
    any of them
}