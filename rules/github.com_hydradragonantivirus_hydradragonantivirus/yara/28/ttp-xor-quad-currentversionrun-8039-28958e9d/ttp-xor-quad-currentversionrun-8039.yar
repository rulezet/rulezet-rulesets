rule TTP_XOR_QUAD_CurrentVersionRun_8039 {
  strings:
    $key_8039 = { d3 56 [2] f7 58 [2] dc 74 [2] f2 56 [2] e6 4d [2] e9 57 [2] f7 4a [2] f5 4b [2] ee 4d [2] f2 4a [2] ee 65 }

  condition:
    any of them
}