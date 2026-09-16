rule TTP_XOR_QUAD_CurrentVersionRun_8041 {
  strings:
    $key_8041 = { d3 2e [2] f7 20 [2] dc 0c [2] f2 2e [2] e6 35 [2] e9 2f [2] f7 32 [2] f5 33 [2] ee 35 [2] f2 32 [2] ee 1d }

  condition:
    any of them
}