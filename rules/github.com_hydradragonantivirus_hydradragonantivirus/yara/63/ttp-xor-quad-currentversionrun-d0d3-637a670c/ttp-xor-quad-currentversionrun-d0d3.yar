rule TTP_XOR_QUAD_CurrentVersionRun_d0d3 {
  strings:
    $key_d0d3 = { 83 bc [2] a7 b2 [2] 8c 9e [2] a2 bc [2] b6 a7 [2] b9 bd [2] a7 a0 [2] a5 a1 [2] be a7 [2] a2 a0 [2] be 8f }

  condition:
    any of them
}