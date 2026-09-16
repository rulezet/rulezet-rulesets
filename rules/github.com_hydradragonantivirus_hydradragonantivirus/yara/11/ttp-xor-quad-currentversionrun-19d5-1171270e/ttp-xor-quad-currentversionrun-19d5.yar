rule TTP_XOR_QUAD_CurrentVersionRun_19d5 {
  strings:
    $key_19d5 = { 4a ba [2] 6e b4 [2] 45 98 [2] 6b ba [2] 7f a1 [2] 70 bb [2] 6e a6 [2] 6c a7 [2] 77 a1 [2] 6b a6 [2] 77 89 }

  condition:
    any of them
}