rule TTP_XOR_QUAD_CurrentVersionRun_807c {
  strings:
    $key_807c = { d3 13 [2] f7 1d [2] dc 31 [2] f2 13 [2] e6 08 [2] e9 12 [2] f7 0f [2] f5 0e [2] ee 08 [2] f2 0f [2] ee 20 }

  condition:
    any of them
}