rule TTP_XOR_QUAD_CurrentVersionRun_b1d3 {
  strings:
    $key_b1d3 = { e2 bc [2] c6 b2 [2] ed 9e [2] c3 bc [2] d7 a7 [2] d8 bd [2] c6 a0 [2] c4 a1 [2] df a7 [2] c3 a0 [2] df 8f }

  condition:
    any of them
}