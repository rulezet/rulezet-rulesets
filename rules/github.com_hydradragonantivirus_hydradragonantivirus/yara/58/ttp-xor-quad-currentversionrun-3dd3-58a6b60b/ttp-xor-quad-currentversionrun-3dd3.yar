rule TTP_XOR_QUAD_CurrentVersionRun_3dd3 {
  strings:
    $key_3dd3 = { 6e bc [2] 4a b2 [2] 61 9e [2] 4f bc [2] 5b a7 [2] 54 bd [2] 4a a0 [2] 48 a1 [2] 53 a7 [2] 4f a0 [2] 53 8f }

  condition:
    any of them
}