rule TTP_XOR_QUAD_CurrentVersionRun_804c {
  strings:
    $key_804c = { d3 23 [2] f7 2d [2] dc 01 [2] f2 23 [2] e6 38 [2] e9 22 [2] f7 3f [2] f5 3e [2] ee 38 [2] f2 3f [2] ee 10 }

  condition:
    any of them
}