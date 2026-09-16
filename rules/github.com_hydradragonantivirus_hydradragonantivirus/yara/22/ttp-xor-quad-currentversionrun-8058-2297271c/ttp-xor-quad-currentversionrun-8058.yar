rule TTP_XOR_QUAD_CurrentVersionRun_8058 {
  strings:
    $key_8058 = { d3 37 [2] f7 39 [2] dc 15 [2] f2 37 [2] e6 2c [2] e9 36 [2] f7 2b [2] f5 2a [2] ee 2c [2] f2 2b [2] ee 04 }

  condition:
    any of them
}