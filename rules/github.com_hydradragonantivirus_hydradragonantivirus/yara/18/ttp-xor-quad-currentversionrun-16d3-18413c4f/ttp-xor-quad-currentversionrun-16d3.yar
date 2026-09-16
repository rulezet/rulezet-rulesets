rule TTP_XOR_QUAD_CurrentVersionRun_16d3 {
  strings:
    $key_16d3 = { 45 bc [2] 61 b2 [2] 4a 9e [2] 64 bc [2] 70 a7 [2] 7f bd [2] 61 a0 [2] 63 a1 [2] 78 a7 [2] 64 a0 [2] 78 8f }

  condition:
    any of them
}