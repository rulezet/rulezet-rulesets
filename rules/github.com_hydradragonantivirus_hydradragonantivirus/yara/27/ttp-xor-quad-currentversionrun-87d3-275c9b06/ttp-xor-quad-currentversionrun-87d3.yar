rule TTP_XOR_QUAD_CurrentVersionRun_87d3 {
  strings:
    $key_87d3 = { d4 bc [2] f0 b2 [2] db 9e [2] f5 bc [2] e1 a7 [2] ee bd [2] f0 a0 [2] f2 a1 [2] e9 a7 [2] f5 a0 [2] e9 8f }

  condition:
    any of them
}