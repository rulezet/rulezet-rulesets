rule TTP_XOR_QUAD_CurrentVersionRun_8053 {
  strings:
    $key_8053 = { d3 3c [2] f7 32 [2] dc 1e [2] f2 3c [2] e6 27 [2] e9 3d [2] f7 20 [2] f5 21 [2] ee 27 [2] f2 20 [2] ee 0f }

  condition:
    any of them
}