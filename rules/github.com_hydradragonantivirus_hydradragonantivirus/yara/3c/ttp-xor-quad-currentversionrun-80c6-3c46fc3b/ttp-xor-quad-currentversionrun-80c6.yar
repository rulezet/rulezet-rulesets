rule TTP_XOR_QUAD_CurrentVersionRun_80c6 {
  strings:
    $key_80c6 = { d3 a9 [2] f7 a7 [2] dc 8b [2] f2 a9 [2] e6 b2 [2] e9 a8 [2] f7 b5 [2] f5 b4 [2] ee b2 [2] f2 b5 [2] ee 9a }

  condition:
    any of them
}