rule TTP_XOR_QUAD_CurrentVersionRun_8065 {
  strings:
    $key_8065 = { d3 0a [2] f7 04 [2] dc 28 [2] f2 0a [2] e6 11 [2] e9 0b [2] f7 16 [2] f5 17 [2] ee 11 [2] f2 16 [2] ee 39 }

  condition:
    any of them
}