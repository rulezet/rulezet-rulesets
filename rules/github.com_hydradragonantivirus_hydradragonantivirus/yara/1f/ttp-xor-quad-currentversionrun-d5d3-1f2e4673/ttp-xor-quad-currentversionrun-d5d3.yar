rule TTP_XOR_QUAD_CurrentVersionRun_d5d3 {
  strings:
    $key_d5d3 = { 86 bc [2] a2 b2 [2] 89 9e [2] a7 bc [2] b3 a7 [2] bc bd [2] a2 a0 [2] a0 a1 [2] bb a7 [2] a7 a0 [2] bb 8f }

  condition:
    any of them
}