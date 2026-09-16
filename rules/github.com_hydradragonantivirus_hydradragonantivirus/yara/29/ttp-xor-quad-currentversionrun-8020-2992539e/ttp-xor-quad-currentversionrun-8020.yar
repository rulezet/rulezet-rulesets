rule TTP_XOR_QUAD_CurrentVersionRun_8020 {
  strings:
    $key_8020 = { d3 4f [2] f7 41 [2] dc 6d [2] f2 4f [2] e6 54 [2] e9 4e [2] f7 53 [2] f5 52 [2] ee 54 [2] f2 53 [2] ee 7c }

  condition:
    any of them
}