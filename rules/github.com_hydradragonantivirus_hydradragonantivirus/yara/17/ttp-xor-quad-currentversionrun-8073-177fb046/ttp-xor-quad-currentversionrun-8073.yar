rule TTP_XOR_QUAD_CurrentVersionRun_8073 {
  strings:
    $key_8073 = { d3 1c [2] f7 12 [2] dc 3e [2] f2 1c [2] e6 07 [2] e9 1d [2] f7 00 [2] f5 01 [2] ee 07 [2] f2 00 [2] ee 2f }

  condition:
    any of them
}