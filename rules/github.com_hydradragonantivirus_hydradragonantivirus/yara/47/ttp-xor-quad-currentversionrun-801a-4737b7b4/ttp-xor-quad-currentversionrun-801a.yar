rule TTP_XOR_QUAD_CurrentVersionRun_801a {
  strings:
    $key_801a = { d3 75 [2] f7 7b [2] dc 57 [2] f2 75 [2] e6 6e [2] e9 74 [2] f7 69 [2] f5 68 [2] ee 6e [2] f2 69 [2] ee 46 }

  condition:
    any of them
}