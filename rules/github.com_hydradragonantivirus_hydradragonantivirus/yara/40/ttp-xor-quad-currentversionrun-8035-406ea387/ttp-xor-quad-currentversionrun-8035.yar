rule TTP_XOR_QUAD_CurrentVersionRun_8035 {
  strings:
    $key_8035 = { d3 5a [2] f7 54 [2] dc 78 [2] f2 5a [2] e6 41 [2] e9 5b [2] f7 46 [2] f5 47 [2] ee 41 [2] f2 46 [2] ee 69 }

  condition:
    any of them
}