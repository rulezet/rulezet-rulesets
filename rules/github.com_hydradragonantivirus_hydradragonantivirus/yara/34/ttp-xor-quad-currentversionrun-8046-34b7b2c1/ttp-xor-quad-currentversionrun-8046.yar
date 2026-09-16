rule TTP_XOR_QUAD_CurrentVersionRun_8046 {
  strings:
    $key_8046 = { d3 29 [2] f7 27 [2] dc 0b [2] f2 29 [2] e6 32 [2] e9 28 [2] f7 35 [2] f5 34 [2] ee 32 [2] f2 35 [2] ee 1a }

  condition:
    any of them
}