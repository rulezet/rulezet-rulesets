rule TTP_XOR_QUAD_CurrentVersionRun_8069 {
  strings:
    $key_8069 = { d3 06 [2] f7 08 [2] dc 24 [2] f2 06 [2] e6 1d [2] e9 07 [2] f7 1a [2] f5 1b [2] ee 1d [2] f2 1a [2] ee 35 }

  condition:
    any of them
}