rule TTP_XOR_QUAD_CurrentVersionRun_8032 {
  strings:
    $key_8032 = { d3 5d [2] f7 53 [2] dc 7f [2] f2 5d [2] e6 46 [2] e9 5c [2] f7 41 [2] f5 40 [2] ee 46 [2] f2 41 [2] ee 6e }

  condition:
    any of them
}