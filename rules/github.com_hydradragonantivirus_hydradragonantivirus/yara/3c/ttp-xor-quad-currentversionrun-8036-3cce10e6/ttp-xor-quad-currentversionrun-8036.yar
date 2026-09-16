rule TTP_XOR_QUAD_CurrentVersionRun_8036 {
  strings:
    $key_8036 = { d3 59 [2] f7 57 [2] dc 7b [2] f2 59 [2] e6 42 [2] e9 58 [2] f7 45 [2] f5 44 [2] ee 42 [2] f2 45 [2] ee 6a }

  condition:
    any of them
}