rule TTP_XOR_QUAD_CurrentVersionRun_49d5 {
  strings:
    $key_49d5 = { 1a ba [2] 3e b4 [2] 15 98 [2] 3b ba [2] 2f a1 [2] 20 bb [2] 3e a6 [2] 3c a7 [2] 27 a1 [2] 3b a6 [2] 27 89 }

  condition:
    any of them
}