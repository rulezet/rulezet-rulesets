rule TTP_XOR_QUAD_CurrentVersionRun_47d3 {
  strings:
    $key_47d3 = { 14 bc [2] 30 b2 [2] 1b 9e [2] 35 bc [2] 21 a7 [2] 2e bd [2] 30 a0 [2] 32 a1 [2] 29 a7 [2] 35 a0 [2] 29 8f }

  condition:
    any of them
}