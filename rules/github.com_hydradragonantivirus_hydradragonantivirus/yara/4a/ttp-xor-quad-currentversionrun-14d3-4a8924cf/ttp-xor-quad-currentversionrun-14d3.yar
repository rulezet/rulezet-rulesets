rule TTP_XOR_QUAD_CurrentVersionRun_14d3 {
  strings:
    $key_14d3 = { 47 bc [2] 63 b2 [2] 48 9e [2] 66 bc [2] 72 a7 [2] 7d bd [2] 63 a0 [2] 61 a1 [2] 7a a7 [2] 66 a0 [2] 7a 8f }

  condition:
    any of them
}