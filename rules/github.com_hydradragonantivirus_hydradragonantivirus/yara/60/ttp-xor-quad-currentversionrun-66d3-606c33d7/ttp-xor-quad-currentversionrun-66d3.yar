rule TTP_XOR_QUAD_CurrentVersionRun_66d3 {
  strings:
    $key_66d3 = { 35 bc [2] 11 b2 [2] 3a 9e [2] 14 bc [2] 00 a7 [2] 0f bd [2] 11 a0 [2] 13 a1 [2] 08 a7 [2] 14 a0 [2] 08 8f }

  condition:
    any of them
}