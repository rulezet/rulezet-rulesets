rule TTP_XOR_QUAD_CurrentVersionRun_80e9 {
  strings:
    $key_80e9 = { d3 86 [2] f7 88 [2] dc a4 [2] f2 86 [2] e6 9d [2] e9 87 [2] f7 9a [2] f5 9b [2] ee 9d [2] f2 9a [2] ee b5 }

  condition:
    any of them
}