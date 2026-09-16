rule TTP_XOR_QUAD_CurrentVersionRun_2cd3 {
  strings:
    $key_2cd3 = { 7f bc [2] 5b b2 [2] 70 9e [2] 5e bc [2] 4a a7 [2] 45 bd [2] 5b a0 [2] 59 a1 [2] 42 a7 [2] 5e a0 [2] 42 8f }

  condition:
    any of them
}