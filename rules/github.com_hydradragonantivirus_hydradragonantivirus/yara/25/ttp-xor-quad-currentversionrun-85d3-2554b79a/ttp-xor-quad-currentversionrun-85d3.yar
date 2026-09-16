rule TTP_XOR_QUAD_CurrentVersionRun_85d3 {
  strings:
    $key_85d3 = { d6 bc [2] f2 b2 [2] d9 9e [2] f7 bc [2] e3 a7 [2] ec bd [2] f2 a0 [2] f0 a1 [2] eb a7 [2] f7 a0 [2] eb 8f }

  condition:
    any of them
}