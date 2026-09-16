rule TTP_XOR_QUAD_CurrentVersionRun_82a7 {
  strings:
    $key_82a7 = { d1 c8 [2] f5 c6 [2] de ea [2] f0 c8 [2] e4 d3 [2] eb c9 [2] f5 d4 [2] f7 d5 [2] ec d3 [2] f0 d4 [2] ec fb }

  condition:
    any of them
}