rule TTP_XOR_QUAD_CurrentVersionRun_80ec {
  strings:
    $key_80ec = { d3 83 [2] f7 8d [2] dc a1 [2] f2 83 [2] e6 98 [2] e9 82 [2] f7 9f [2] f5 9e [2] ee 98 [2] f2 9f [2] ee b0 }

  condition:
    any of them
}