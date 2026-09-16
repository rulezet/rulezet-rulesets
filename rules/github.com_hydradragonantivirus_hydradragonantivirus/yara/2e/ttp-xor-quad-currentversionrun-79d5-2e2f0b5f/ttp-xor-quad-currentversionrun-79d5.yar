rule TTP_XOR_QUAD_CurrentVersionRun_79d5 {
  strings:
    $key_79d5 = { 2a ba [2] 0e b4 [2] 25 98 [2] 0b ba [2] 1f a1 [2] 10 bb [2] 0e a6 [2] 0c a7 [2] 17 a1 [2] 0b a6 [2] 17 89 }

  condition:
    any of them
}