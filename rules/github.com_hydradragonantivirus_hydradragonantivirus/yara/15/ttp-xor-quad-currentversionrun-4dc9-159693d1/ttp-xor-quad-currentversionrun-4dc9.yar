rule TTP_XOR_QUAD_CurrentVersionRun_4dc9 {
  strings:
    $key_4dc9 = { 1e a6 [2] 3a a8 [2] 11 84 [2] 3f a6 [2] 2b bd [2] 24 a7 [2] 3a ba [2] 38 bb [2] 23 bd [2] 3f ba [2] 23 95 }

  condition:
    any of them
}