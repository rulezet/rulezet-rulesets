rule TTP_XOR_QUAD_CurrentVersionRun_80a7 {
  strings:
    $key_80a7 = { d3 c8 [2] f7 c6 [2] dc ea [2] f2 c8 [2] e6 d3 [2] e9 c9 [2] f7 d4 [2] f5 d5 [2] ee d3 [2] f2 d4 [2] ee fb }

  condition:
    any of them
}