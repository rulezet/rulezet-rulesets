rule TTP_XOR_QUAD_CurrentVersionRun_805c {
  strings:
    $key_805c = { d3 33 [2] f7 3d [2] dc 11 [2] f2 33 [2] e6 28 [2] e9 32 [2] f7 2f [2] f5 2e [2] ee 28 [2] f2 2f [2] ee 00 }

  condition:
    any of them
}