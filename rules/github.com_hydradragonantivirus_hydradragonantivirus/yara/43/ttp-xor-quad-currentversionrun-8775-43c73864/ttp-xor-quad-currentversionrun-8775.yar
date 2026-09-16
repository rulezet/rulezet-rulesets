rule TTP_XOR_QUAD_CurrentVersionRun_8775 {
  strings:
    $key_8775 = { d4 1a [2] f0 14 [2] db 38 [2] f5 1a [2] e1 01 [2] ee 1b [2] f0 06 [2] f2 07 [2] e9 01 [2] f5 06 [2] e9 29 }

  condition:
    any of them
}