rule TTP_XOR_QUAD_CurrentVersionRun_805f {
  strings:
    $key_805f = { d3 30 [2] f7 3e [2] dc 12 [2] f2 30 [2] e6 2b [2] e9 31 [2] f7 2c [2] f5 2d [2] ee 2b [2] f2 2c [2] ee 03 }

  condition:
    any of them
}