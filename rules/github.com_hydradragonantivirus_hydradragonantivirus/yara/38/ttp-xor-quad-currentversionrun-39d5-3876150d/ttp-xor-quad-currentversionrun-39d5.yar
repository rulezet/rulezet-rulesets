rule TTP_XOR_QUAD_CurrentVersionRun_39d5 {
  strings:
    $key_39d5 = { 6a ba [2] 4e b4 [2] 65 98 [2] 4b ba [2] 5f a1 [2] 50 bb [2] 4e a6 [2] 4c a7 [2] 57 a1 [2] 4b a6 [2] 57 89 }

  condition:
    any of them
}