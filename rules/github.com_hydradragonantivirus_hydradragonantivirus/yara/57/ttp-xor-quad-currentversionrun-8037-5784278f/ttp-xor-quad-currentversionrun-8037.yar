rule TTP_XOR_QUAD_CurrentVersionRun_8037 {
  strings:
    $key_8037 = { d3 58 [2] f7 56 [2] dc 7a [2] f2 58 [2] e6 43 [2] e9 59 [2] f7 44 [2] f5 45 [2] ee 43 [2] f2 44 [2] ee 6b }

  condition:
    any of them
}