rule TTP_XOR_QUAD_CurrentVersionRun_80c5 {
  strings:
    $key_80c5 = { d3 aa [2] f7 a4 [2] dc 88 [2] f2 aa [2] e6 b1 [2] e9 ab [2] f7 b6 [2] f5 b7 [2] ee b1 [2] f2 b6 [2] ee 99 }

  condition:
    any of them
}