rule TTP_XOR_QUAD_CurrentVersionRun_0cd3 {
  strings:
    $key_0cd3 = { 5f bc [2] 7b b2 [2] 50 9e [2] 7e bc [2] 6a a7 [2] 65 bd [2] 7b a0 [2] 79 a1 [2] 62 a7 [2] 7e a0 [2] 62 8f }

  condition:
    any of them
}