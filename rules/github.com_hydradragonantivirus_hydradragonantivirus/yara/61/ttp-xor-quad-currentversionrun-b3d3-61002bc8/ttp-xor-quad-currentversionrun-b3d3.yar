rule TTP_XOR_QUAD_CurrentVersionRun_b3d3 {
  strings:
    $key_b3d3 = { e0 bc [2] c4 b2 [2] ef 9e [2] c1 bc [2] d5 a7 [2] da bd [2] c4 a0 [2] c6 a1 [2] dd a7 [2] c1 a0 [2] dd 8f }

  condition:
    any of them
}