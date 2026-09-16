rule TTP_XOR_QUAD_CurrentVersionRun_80ef {
  strings:
    $key_80ef = { d3 80 [2] f7 8e [2] dc a2 [2] f2 80 [2] e6 9b [2] e9 81 [2] f7 9c [2] f5 9d [2] ee 9b [2] f2 9c [2] ee b3 }

  condition:
    any of them
}