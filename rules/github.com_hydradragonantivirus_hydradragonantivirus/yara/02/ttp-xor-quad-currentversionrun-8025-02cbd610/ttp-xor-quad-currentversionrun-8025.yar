rule TTP_XOR_QUAD_CurrentVersionRun_8025 {
  strings:
    $key_8025 = { d3 4a [2] f7 44 [2] dc 68 [2] f2 4a [2] e6 51 [2] e9 4b [2] f7 56 [2] f5 57 [2] ee 51 [2] f2 56 [2] ee 79 }

  condition:
    any of them
}