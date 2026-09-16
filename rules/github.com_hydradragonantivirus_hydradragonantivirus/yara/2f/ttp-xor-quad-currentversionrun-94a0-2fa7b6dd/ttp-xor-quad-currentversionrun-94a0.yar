rule TTP_XOR_QUAD_CurrentVersionRun_94a0 {
  strings:
    $key_94a0 = { c7 cf [2] e3 c1 [2] c8 ed [2] e6 cf [2] f2 d4 [2] fd ce [2] e3 d3 [2] e1 d2 [2] fa d4 [2] e6 d3 [2] fa fc }

  condition:
    any of them
}