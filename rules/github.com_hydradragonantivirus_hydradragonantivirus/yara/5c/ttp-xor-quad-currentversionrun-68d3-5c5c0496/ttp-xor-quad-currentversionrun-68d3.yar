rule TTP_XOR_QUAD_CurrentVersionRun_68d3 {
  strings:
    $key_68d3 = { 3b bc [2] 1f b2 [2] 34 9e [2] 1a bc [2] 0e a7 [2] 01 bd [2] 1f a0 [2] 1d a1 [2] 06 a7 [2] 1a a0 [2] 06 8f }

  condition:
    any of them
}