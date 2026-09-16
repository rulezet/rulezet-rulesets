rule TTP_XOR_QUAD_CurrentVersionRun_3cc9 {
  strings:
    $key_3cc9 = { 6f a6 [2] 4b a8 [2] 60 84 [2] 4e a6 [2] 5a bd [2] 55 a7 [2] 4b ba [2] 49 bb [2] 52 bd [2] 4e ba [2] 52 95 }

  condition:
    any of them
}