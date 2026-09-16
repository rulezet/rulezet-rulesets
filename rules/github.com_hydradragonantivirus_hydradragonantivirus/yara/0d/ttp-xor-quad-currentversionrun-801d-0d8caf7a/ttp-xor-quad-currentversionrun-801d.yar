rule TTP_XOR_QUAD_CurrentVersionRun_801d {
  strings:
    $key_801d = { d3 72 [2] f7 7c [2] dc 50 [2] f2 72 [2] e6 69 [2] e9 73 [2] f7 6e [2] f5 6f [2] ee 69 [2] f2 6e [2] ee 41 }

  condition:
    any of them
}