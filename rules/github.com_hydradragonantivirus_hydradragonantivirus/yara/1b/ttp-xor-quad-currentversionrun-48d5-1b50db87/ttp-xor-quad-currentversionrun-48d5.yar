rule TTP_XOR_QUAD_CurrentVersionRun_48d5 {
  strings:
    $key_48d5 = { 1b ba [2] 3f b4 [2] 14 98 [2] 3a ba [2] 2e a1 [2] 21 bb [2] 3f a6 [2] 3d a7 [2] 26 a1 [2] 3a a6 [2] 26 89 }

  condition:
    any of them
}