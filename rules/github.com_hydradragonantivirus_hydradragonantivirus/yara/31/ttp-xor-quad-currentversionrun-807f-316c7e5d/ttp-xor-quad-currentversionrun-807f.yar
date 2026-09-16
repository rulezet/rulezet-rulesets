rule TTP_XOR_QUAD_CurrentVersionRun_807f {
  strings:
    $key_807f = { d3 10 [2] f7 1e [2] dc 32 [2] f2 10 [2] e6 0b [2] e9 11 [2] f7 0c [2] f5 0d [2] ee 0b [2] f2 0c [2] ee 23 }

  condition:
    any of them
}