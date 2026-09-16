rule TTP_XOR_QUAD_CurrentVersionRun_c3d3 {
  strings:
    $key_c3d3 = { 90 bc [2] b4 b2 [2] 9f 9e [2] b1 bc [2] a5 a7 [2] aa bd [2] b4 a0 [2] b6 a1 [2] ad a7 [2] b1 a0 [2] ad 8f }

  condition:
    any of them
}