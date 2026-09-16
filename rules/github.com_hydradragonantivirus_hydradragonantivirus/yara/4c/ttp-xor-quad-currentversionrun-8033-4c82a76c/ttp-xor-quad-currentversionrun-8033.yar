rule TTP_XOR_QUAD_CurrentVersionRun_8033 {
  strings:
    $key_8033 = { d3 5c [2] f7 52 [2] dc 7e [2] f2 5c [2] e6 47 [2] e9 5d [2] f7 40 [2] f5 41 [2] ee 47 [2] f2 40 [2] ee 6f }

  condition:
    any of them
}