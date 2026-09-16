rule TTP_XOR_QUAD_CurrentVersionRun_8018 {
  strings:
    $key_8018 = { d3 77 [2] f7 79 [2] dc 55 [2] f2 77 [2] e6 6c [2] e9 76 [2] f7 6b [2] f5 6a [2] ee 6c [2] f2 6b [2] ee 44 }

  condition:
    any of them
}