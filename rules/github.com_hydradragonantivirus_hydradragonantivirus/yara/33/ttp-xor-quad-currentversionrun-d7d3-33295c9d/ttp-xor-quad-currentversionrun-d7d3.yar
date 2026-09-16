rule TTP_XOR_QUAD_CurrentVersionRun_d7d3 {
  strings:
    $key_d7d3 = { 84 bc [2] a0 b2 [2] 8b 9e [2] a5 bc [2] b1 a7 [2] be bd [2] a0 a0 [2] a2 a1 [2] b9 a7 [2] a5 a0 [2] b9 8f }

  condition:
    any of them
}