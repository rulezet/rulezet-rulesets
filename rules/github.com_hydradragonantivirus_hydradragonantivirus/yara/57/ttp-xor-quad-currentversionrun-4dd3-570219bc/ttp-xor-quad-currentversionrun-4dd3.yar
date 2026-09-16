rule TTP_XOR_QUAD_CurrentVersionRun_4dd3 {
  strings:
    $key_4dd3 = { 1e bc [2] 3a b2 [2] 11 9e [2] 3f bc [2] 2b a7 [2] 24 bd [2] 3a a0 [2] 38 a1 [2] 23 a7 [2] 3f a0 [2] 23 8f }

  condition:
    any of them
}