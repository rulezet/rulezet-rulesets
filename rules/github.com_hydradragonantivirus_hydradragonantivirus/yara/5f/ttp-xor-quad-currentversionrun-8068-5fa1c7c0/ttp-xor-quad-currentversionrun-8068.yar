rule TTP_XOR_QUAD_CurrentVersionRun_8068 {
  strings:
    $key_8068 = { d3 07 [2] f7 09 [2] dc 25 [2] f2 07 [2] e6 1c [2] e9 06 [2] f7 1b [2] f5 1a [2] ee 1c [2] f2 1b [2] ee 34 }

  condition:
    any of them
}