rule TTP_XOR_QUAD_CurrentVersionRun_07d3 {
  strings:
    $key_07d3 = { 54 bc [2] 70 b2 [2] 5b 9e [2] 75 bc [2] 61 a7 [2] 6e bd [2] 70 a0 [2] 72 a1 [2] 69 a7 [2] 75 a0 [2] 69 8f }

  condition:
    any of them
}