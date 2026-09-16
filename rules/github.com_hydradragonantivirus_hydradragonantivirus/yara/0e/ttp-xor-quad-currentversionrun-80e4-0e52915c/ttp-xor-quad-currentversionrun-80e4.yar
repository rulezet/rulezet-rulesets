rule TTP_XOR_QUAD_CurrentVersionRun_80e4 {
  strings:
    $key_80e4 = { d3 8b [2] f7 85 [2] dc a9 [2] f2 8b [2] e6 90 [2] e9 8a [2] f7 97 [2] f5 96 [2] ee 90 [2] f2 97 [2] ee b8 }

  condition:
    any of them
}