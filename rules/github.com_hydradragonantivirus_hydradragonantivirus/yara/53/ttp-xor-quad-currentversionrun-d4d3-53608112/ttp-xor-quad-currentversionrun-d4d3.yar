rule TTP_XOR_QUAD_CurrentVersionRun_d4d3 {
  strings:
    $key_d4d3 = { 87 bc [2] a3 b2 [2] 88 9e [2] a6 bc [2] b2 a7 [2] bd bd [2] a3 a0 [2] a1 a1 [2] ba a7 [2] a6 a0 [2] ba 8f }

  condition:
    any of them
}