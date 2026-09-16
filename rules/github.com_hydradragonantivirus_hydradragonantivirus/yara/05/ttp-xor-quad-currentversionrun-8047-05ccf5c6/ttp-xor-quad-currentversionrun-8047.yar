rule TTP_XOR_QUAD_CurrentVersionRun_8047 {
  strings:
    $key_8047 = { d3 28 [2] f7 26 [2] dc 0a [2] f2 28 [2] e6 33 [2] e9 29 [2] f7 34 [2] f5 35 [2] ee 33 [2] f2 34 [2] ee 1b }

  condition:
    any of them
}