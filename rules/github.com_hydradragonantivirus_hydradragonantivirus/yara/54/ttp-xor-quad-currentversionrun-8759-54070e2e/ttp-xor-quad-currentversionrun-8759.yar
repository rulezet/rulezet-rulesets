rule TTP_XOR_QUAD_CurrentVersionRun_8759 {
  strings:
    $key_8759 = { d4 36 [2] f0 38 [2] db 14 [2] f5 36 [2] e1 2d [2] ee 37 [2] f0 2a [2] f2 2b [2] e9 2d [2] f5 2a [2] e9 05 }

  condition:
    any of them
}