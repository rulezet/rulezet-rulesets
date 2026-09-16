rule TTP_XOR_QUAD_CurrentVersionRun_8022 {
  strings:
    $key_8022 = { d3 4d [2] f7 43 [2] dc 6f [2] f2 4d [2] e6 56 [2] e9 4c [2] f7 51 [2] f5 50 [2] ee 56 [2] f2 51 [2] ee 7e }

  condition:
    any of them
}