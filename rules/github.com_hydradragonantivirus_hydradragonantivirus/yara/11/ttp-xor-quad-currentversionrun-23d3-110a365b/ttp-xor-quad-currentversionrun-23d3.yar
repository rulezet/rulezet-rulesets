rule TTP_XOR_QUAD_CurrentVersionRun_23d3 {
  strings:
    $key_23d3 = { 70 bc [2] 54 b2 [2] 7f 9e [2] 51 bc [2] 45 a7 [2] 4a bd [2] 54 a0 [2] 56 a1 [2] 4d a7 [2] 51 a0 [2] 4d 8f }

  condition:
    any of them
}