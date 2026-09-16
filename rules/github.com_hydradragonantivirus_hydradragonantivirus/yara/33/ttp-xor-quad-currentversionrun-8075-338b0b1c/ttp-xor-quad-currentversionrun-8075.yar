rule TTP_XOR_QUAD_CurrentVersionRun_8075 {
  strings:
    $key_8075 = { d3 1a [2] f7 14 [2] dc 38 [2] f2 1a [2] e6 01 [2] e9 1b [2] f7 06 [2] f5 07 [2] ee 01 [2] f2 06 [2] ee 29 }

  condition:
    any of them
}