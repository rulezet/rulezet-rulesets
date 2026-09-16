rule TTP_XOR_QUAD_CurrentVersionRun_801b {
  strings:
    $key_801b = { d3 74 [2] f7 7a [2] dc 56 [2] f2 74 [2] e6 6f [2] e9 75 [2] f7 68 [2] f5 69 [2] ee 6f [2] f2 68 [2] ee 47 }

  condition:
    any of them
}