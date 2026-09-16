rule TTP_XOR_QUAD_CurrentVersionRun_03d3 {
  strings:
    $key_03d3 = { 50 bc [2] 74 b2 [2] 5f 9e [2] 71 bc [2] 65 a7 [2] 6a bd [2] 74 a0 [2] 76 a1 [2] 6d a7 [2] 71 a0 [2] 6d 8f }

  condition:
    any of them
}