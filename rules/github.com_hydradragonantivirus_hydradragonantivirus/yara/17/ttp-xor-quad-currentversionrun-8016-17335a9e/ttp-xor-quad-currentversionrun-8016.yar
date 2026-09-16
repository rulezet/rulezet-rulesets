rule TTP_XOR_QUAD_CurrentVersionRun_8016 {
  strings:
    $key_8016 = { d3 79 [2] f7 77 [2] dc 5b [2] f2 79 [2] e6 62 [2] e9 78 [2] f7 65 [2] f5 64 [2] ee 62 [2] f2 65 [2] ee 4a }

  condition:
    any of them
}