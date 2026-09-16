rule TTP_XOR_QUAD_CurrentVersionRun_3cd3 {
  strings:
    $key_3cd3 = { 6f bc [2] 4b b2 [2] 60 9e [2] 4e bc [2] 5a a7 [2] 55 bd [2] 4b a0 [2] 49 a1 [2] 52 a7 [2] 4e a0 [2] 52 8f }

  condition:
    any of them
}