rule TTP_XOR_QUAD_CurrentVersionRun_80f1 {
  strings:
    $key_80f1 = { d3 9e [2] f7 90 [2] dc bc [2] f2 9e [2] e6 85 [2] e9 9f [2] f7 82 [2] f5 83 [2] ee 85 [2] f2 82 [2] ee ad }

  condition:
    any of them
}