rule TTP_XOR_QUAD_CurrentVersionRun_8017 {
  strings:
    $key_8017 = { d3 78 [2] f7 76 [2] dc 5a [2] f2 78 [2] e6 63 [2] e9 79 [2] f7 64 [2] f5 65 [2] ee 63 [2] f2 64 [2] ee 4b }

  condition:
    any of them
}