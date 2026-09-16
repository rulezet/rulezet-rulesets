rule TTP_XOR_QUAD_CurrentVersionRun_8023 {
  strings:
    $key_8023 = { d3 4c [2] f7 42 [2] dc 6e [2] f2 4c [2] e6 57 [2] e9 4d [2] f7 50 [2] f5 51 [2] ee 57 [2] f2 50 [2] ee 7f }

  condition:
    any of them
}