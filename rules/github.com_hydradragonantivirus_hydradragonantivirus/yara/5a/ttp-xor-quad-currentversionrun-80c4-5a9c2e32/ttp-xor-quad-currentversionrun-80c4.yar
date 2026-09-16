rule TTP_XOR_QUAD_CurrentVersionRun_80c4 {
  strings:
    $key_80c4 = { d3 ab [2] f7 a5 [2] dc 89 [2] f2 ab [2] e6 b0 [2] e9 aa [2] f7 b7 [2] f5 b6 [2] ee b0 [2] f2 b7 [2] ee 98 }

  condition:
    any of them
}