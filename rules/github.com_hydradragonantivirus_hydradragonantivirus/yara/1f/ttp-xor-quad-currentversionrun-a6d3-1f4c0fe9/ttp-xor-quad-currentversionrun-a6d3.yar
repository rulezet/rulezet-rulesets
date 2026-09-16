rule TTP_XOR_QUAD_CurrentVersionRun_a6d3 {
  strings:
    $key_a6d3 = { f5 bc [2] d1 b2 [2] fa 9e [2] d4 bc [2] c0 a7 [2] cf bd [2] d1 a0 [2] d3 a1 [2] c8 a7 [2] d4 a0 [2] c8 8f }

  condition:
    any of them
}