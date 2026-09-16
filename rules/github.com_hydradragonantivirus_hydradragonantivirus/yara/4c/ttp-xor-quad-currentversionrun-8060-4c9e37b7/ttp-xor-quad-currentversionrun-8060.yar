rule TTP_XOR_QUAD_CurrentVersionRun_8060 {
  strings:
    $key_8060 = { d3 0f [2] f7 01 [2] dc 2d [2] f2 0f [2] e6 14 [2] e9 0e [2] f7 13 [2] f5 12 [2] ee 14 [2] f2 13 [2] ee 3c }

  condition:
    any of them
}