rule TTP_XOR_QUAD_CurrentVersionRun_8038 {
  strings:
    $key_8038 = { d3 57 [2] f7 59 [2] dc 75 [2] f2 57 [2] e6 4c [2] e9 56 [2] f7 4b [2] f5 4a [2] ee 4c [2] f2 4b [2] ee 64 }

  condition:
    any of them
}