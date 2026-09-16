rule TTP_XOR_QUAD_CurrentVersionRun_1dd3 {
  strings:
    $key_1dd3 = { 4e bc [2] 6a b2 [2] 41 9e [2] 6f bc [2] 7b a7 [2] 74 bd [2] 6a a0 [2] 68 a1 [2] 73 a7 [2] 6f a0 [2] 73 8f }

  condition:
    any of them
}