rule TTP_XOR_QUAD_CurrentVersionRun_53d3 {
  strings:
    $key_53d3 = { 00 bc [2] 24 b2 [2] 0f 9e [2] 21 bc [2] 35 a7 [2] 3a bd [2] 24 a0 [2] 26 a1 [2] 3d a7 [2] 21 a0 [2] 3d 8f }

  condition:
    any of them
}