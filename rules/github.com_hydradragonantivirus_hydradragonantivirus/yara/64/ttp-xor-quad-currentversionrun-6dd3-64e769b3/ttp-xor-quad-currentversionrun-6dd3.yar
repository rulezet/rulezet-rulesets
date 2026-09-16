rule TTP_XOR_QUAD_CurrentVersionRun_6dd3 {
  strings:
    $key_6dd3 = { 3e bc [2] 1a b2 [2] 31 9e [2] 1f bc [2] 0b a7 [2] 04 bd [2] 1a a0 [2] 18 a1 [2] 03 a7 [2] 1f a0 [2] 03 8f }

  condition:
    any of them
}