rule TTP_XOR_QUAD_CurrentVersionRun_93a0 {
  strings:
    $key_93a0 = { c0 cf [2] e4 c1 [2] cf ed [2] e1 cf [2] f5 d4 [2] fa ce [2] e4 d3 [2] e6 d2 [2] fd d4 [2] e1 d3 [2] fd fc }

  condition:
    any of them
}