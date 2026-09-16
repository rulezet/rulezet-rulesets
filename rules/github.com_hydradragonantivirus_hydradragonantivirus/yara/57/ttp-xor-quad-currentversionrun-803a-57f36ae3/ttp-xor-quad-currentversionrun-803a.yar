rule TTP_XOR_QUAD_CurrentVersionRun_803a {
  strings:
    $key_803a = { d3 55 [2] f7 5b [2] dc 77 [2] f2 55 [2] e6 4e [2] e9 54 [2] f7 49 [2] f5 48 [2] ee 4e [2] f2 49 [2] ee 66 }

  condition:
    any of them
}