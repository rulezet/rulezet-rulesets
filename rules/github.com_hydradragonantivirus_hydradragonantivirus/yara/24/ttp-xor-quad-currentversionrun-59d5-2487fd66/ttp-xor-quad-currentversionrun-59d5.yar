rule TTP_XOR_QUAD_CurrentVersionRun_59d5 {
  strings:
    $key_59d5 = { 0a ba [2] 2e b4 [2] 05 98 [2] 2b ba [2] 3f a1 [2] 30 bb [2] 2e a6 [2] 2c a7 [2] 37 a1 [2] 2b a6 [2] 37 89 }

  condition:
    any of them
}