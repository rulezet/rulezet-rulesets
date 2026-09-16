rule TTP_XOR_QUAD_CurrentVersionRun_8001 {
  strings:
    $key_8001 = { d3 6e [2] f7 60 [2] dc 4c [2] f2 6e [2] e6 75 [2] e9 6f [2] f7 72 [2] f5 73 [2] ee 75 [2] f2 72 [2] ee 5d }

  condition:
    any of them
}