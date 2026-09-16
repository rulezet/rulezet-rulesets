rule TTP_XOR_QUAD_CurrentVersionRun_80e8 {
  strings:
    $key_80e8 = { d3 87 [2] f7 89 [2] dc a5 [2] f2 87 [2] e6 9c [2] e9 86 [2] f7 9b [2] f5 9a [2] ee 9c [2] f2 9b [2] ee b4 }

  condition:
    any of them
}