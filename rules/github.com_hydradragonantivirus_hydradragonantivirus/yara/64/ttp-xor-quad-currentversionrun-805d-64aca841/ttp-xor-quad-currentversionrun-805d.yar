rule TTP_XOR_QUAD_CurrentVersionRun_805d {
  strings:
    $key_805d = { d3 32 [2] f7 3c [2] dc 10 [2] f2 32 [2] e6 29 [2] e9 33 [2] f7 2e [2] f5 2f [2] ee 29 [2] f2 2e [2] ee 01 }

  condition:
    any of them
}