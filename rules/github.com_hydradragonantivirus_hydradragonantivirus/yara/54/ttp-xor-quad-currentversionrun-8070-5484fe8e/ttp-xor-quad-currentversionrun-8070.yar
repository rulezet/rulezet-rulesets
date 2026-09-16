rule TTP_XOR_QUAD_CurrentVersionRun_8070 {
  strings:
    $key_8070 = { d3 1f [2] f7 11 [2] dc 3d [2] f2 1f [2] e6 04 [2] e9 1e [2] f7 03 [2] f5 02 [2] ee 04 [2] f2 03 [2] ee 2c }

  condition:
    any of them
}