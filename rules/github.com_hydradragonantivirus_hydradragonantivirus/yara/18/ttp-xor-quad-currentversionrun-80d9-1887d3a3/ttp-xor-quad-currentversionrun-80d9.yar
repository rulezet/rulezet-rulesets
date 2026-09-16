rule TTP_XOR_QUAD_CurrentVersionRun_80d9 {
  strings:
    $key_80d9 = { d3 b6 [2] f7 b8 [2] dc 94 [2] f2 b6 [2] e6 ad [2] e9 b7 [2] f7 aa [2] f5 ab [2] ee ad [2] f2 aa [2] ee 85 }

  condition:
    any of them
}