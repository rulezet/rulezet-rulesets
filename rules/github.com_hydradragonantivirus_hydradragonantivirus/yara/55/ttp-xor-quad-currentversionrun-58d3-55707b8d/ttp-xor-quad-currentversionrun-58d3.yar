rule TTP_XOR_QUAD_CurrentVersionRun_58d3 {
  strings:
    $key_58d3 = { 0b bc [2] 2f b2 [2] 04 9e [2] 2a bc [2] 3e a7 [2] 31 bd [2] 2f a0 [2] 2d a1 [2] 36 a7 [2] 2a a0 [2] 36 8f }

  condition:
    any of them
}