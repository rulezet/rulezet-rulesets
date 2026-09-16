rule TTP_XOR_QUAD_CurrentVersionRun_8072 {
  strings:
    $key_8072 = { d3 1d [2] f7 13 [2] dc 3f [2] f2 1d [2] e6 06 [2] e9 1c [2] f7 01 [2] f5 00 [2] ee 06 [2] f2 01 [2] ee 2e }

  condition:
    any of them
}