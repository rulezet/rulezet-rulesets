rule TTP_XOR_QUAD_CurrentVersionRun_78d5 {
  strings:
    $key_78d5 = { 2b ba [2] 0f b4 [2] 24 98 [2] 0a ba [2] 1e a1 [2] 11 bb [2] 0f a6 [2] 0d a7 [2] 16 a1 [2] 0a a6 [2] 16 89 }

  condition:
    any of them
}