rule TTP_XOR_QUAD_CurrentVersionRun_b4d3 {
  strings:
    $key_b4d3 = { e7 bc [2] c3 b2 [2] e8 9e [2] c6 bc [2] d2 a7 [2] dd bd [2] c3 a0 [2] c1 a1 [2] da a7 [2] c6 a0 [2] da 8f }

  condition:
    any of them
}