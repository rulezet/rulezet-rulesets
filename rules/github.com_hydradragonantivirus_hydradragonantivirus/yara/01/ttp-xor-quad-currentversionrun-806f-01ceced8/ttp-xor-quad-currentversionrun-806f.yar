rule TTP_XOR_QUAD_CurrentVersionRun_806f {
  strings:
    $key_806f = { d3 00 [2] f7 0e [2] dc 22 [2] f2 00 [2] e6 1b [2] e9 01 [2] f7 1c [2] f5 1d [2] ee 1b [2] f2 1c [2] ee 33 }

  condition:
    any of them
}