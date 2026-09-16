rule TTP_XOR_QUAD_CurrentVersionRun_c6d3 {
  strings:
    $key_c6d3 = { 95 bc [2] b1 b2 [2] 9a 9e [2] b4 bc [2] a0 a7 [2] af bd [2] b1 a0 [2] b3 a1 [2] a8 a7 [2] b4 a0 [2] a8 8f }

  condition:
    any of them
}