rule TTP_XOR_QUAD_CurrentVersionRun_fdd3 {
  strings:
    $key_fdd3 = { ae bc [2] 8a b2 [2] a1 9e [2] 8f bc [2] 9b a7 [2] 94 bd [2] 8a a0 [2] 88 a1 [2] 93 a7 [2] 8f a0 [2] 93 8f }

  condition:
    any of them
}