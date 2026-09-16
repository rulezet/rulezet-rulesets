rule TTP_XOR_QUAD_CurrentVersionRun_8045 {
  strings:
    $key_8045 = { d3 2a [2] f7 24 [2] dc 08 [2] f2 2a [2] e6 31 [2] e9 2b [2] f7 36 [2] f5 37 [2] ee 31 [2] f2 36 [2] ee 19 }

  condition:
    any of them
}