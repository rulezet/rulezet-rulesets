rule TTP_XOR_QUAD_CurrentVersionRun_803d {
  strings:
    $key_803d = { d3 52 [2] f7 5c [2] dc 70 [2] f2 52 [2] e6 49 [2] e9 53 [2] f7 4e [2] f5 4f [2] ee 49 [2] f2 4e [2] ee 61 }

  condition:
    any of them
}