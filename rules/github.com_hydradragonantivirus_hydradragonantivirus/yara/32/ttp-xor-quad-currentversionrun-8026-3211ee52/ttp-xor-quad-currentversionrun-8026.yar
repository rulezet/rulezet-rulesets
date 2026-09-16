rule TTP_XOR_QUAD_CurrentVersionRun_8026 {
  strings:
    $key_8026 = { d3 49 [2] f7 47 [2] dc 6b [2] f2 49 [2] e6 52 [2] e9 48 [2] f7 55 [2] f5 54 [2] ee 52 [2] f2 55 [2] ee 7a }

  condition:
    any of them
}