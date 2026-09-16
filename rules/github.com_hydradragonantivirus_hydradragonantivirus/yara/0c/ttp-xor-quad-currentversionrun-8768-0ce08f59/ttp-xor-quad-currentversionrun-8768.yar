rule TTP_XOR_QUAD_CurrentVersionRun_8768 {
  strings:
    $key_8768 = { d4 07 [2] f0 09 [2] db 25 [2] f5 07 [2] e1 1c [2] ee 06 [2] f0 1b [2] f2 1a [2] e9 1c [2] f5 1b [2] e9 34 }

  condition:
    any of them
}