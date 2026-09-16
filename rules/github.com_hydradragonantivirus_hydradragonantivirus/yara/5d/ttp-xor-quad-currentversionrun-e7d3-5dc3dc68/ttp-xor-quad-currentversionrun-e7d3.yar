rule TTP_XOR_QUAD_CurrentVersionRun_e7d3 {
  strings:
    $key_e7d3 = { b4 bc [2] 90 b2 [2] bb 9e [2] 95 bc [2] 81 a7 [2] 8e bd [2] 90 a0 [2] 92 a1 [2] 89 a7 [2] 95 a0 [2] 89 8f }

  condition:
    any of them
}