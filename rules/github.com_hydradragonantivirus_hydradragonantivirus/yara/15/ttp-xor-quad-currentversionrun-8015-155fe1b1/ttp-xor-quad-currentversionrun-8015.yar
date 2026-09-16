rule TTP_XOR_QUAD_CurrentVersionRun_8015 {
  strings:
    $key_8015 = { d3 7a [2] f7 74 [2] dc 58 [2] f2 7a [2] e6 61 [2] e9 7b [2] f7 66 [2] f5 67 [2] ee 61 [2] f2 66 [2] ee 49 }

  condition:
    any of them
}