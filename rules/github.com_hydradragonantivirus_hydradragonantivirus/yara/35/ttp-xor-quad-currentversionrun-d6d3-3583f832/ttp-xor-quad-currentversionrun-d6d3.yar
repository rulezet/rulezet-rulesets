rule TTP_XOR_QUAD_CurrentVersionRun_d6d3 {
  strings:
    $key_d6d3 = { 85 bc [2] a1 b2 [2] 8a 9e [2] a4 bc [2] b0 a7 [2] bf bd [2] a1 a0 [2] a3 a1 [2] b8 a7 [2] a4 a0 [2] b8 8f }

  condition:
    any of them
}