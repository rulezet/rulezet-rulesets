rule TTP_XOR_QUAD_CurrentVersionRun_37d3 {
  strings:
    $key_37d3 = { 64 bc [2] 40 b2 [2] 6b 9e [2] 45 bc [2] 51 a7 [2] 5e bd [2] 40 a0 [2] 42 a1 [2] 59 a7 [2] 45 a0 [2] 59 8f }

  condition:
    any of them
}