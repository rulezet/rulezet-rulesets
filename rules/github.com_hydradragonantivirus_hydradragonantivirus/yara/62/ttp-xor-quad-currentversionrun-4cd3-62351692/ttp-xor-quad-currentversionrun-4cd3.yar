rule TTP_XOR_QUAD_CurrentVersionRun_4cd3 {
  strings:
    $key_4cd3 = { 1f bc [2] 3b b2 [2] 10 9e [2] 3e bc [2] 2a a7 [2] 25 bd [2] 3b a0 [2] 39 a1 [2] 22 a7 [2] 3e a0 [2] 22 8f }

  condition:
    any of them
}