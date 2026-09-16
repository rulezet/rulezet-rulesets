rule TTP_XOR_QUAD_CurrentVersionRun_93d3 {
  strings:
    $key_93d3 = { c0 bc [2] e4 b2 [2] cf 9e [2] e1 bc [2] f5 a7 [2] fa bd [2] e4 a0 [2] e6 a1 [2] fd a7 [2] e1 a0 [2] fd 8f }

  condition:
    any of them
}