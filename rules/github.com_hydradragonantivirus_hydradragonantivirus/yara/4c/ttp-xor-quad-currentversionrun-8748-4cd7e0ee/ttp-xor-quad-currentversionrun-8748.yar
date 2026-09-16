rule TTP_XOR_QUAD_CurrentVersionRun_8748 {
  strings:
    $key_8748 = { d4 27 [2] f0 29 [2] db 05 [2] f5 27 [2] e1 3c [2] ee 26 [2] f0 3b [2] f2 3a [2] e9 3c [2] f5 3b [2] e9 14 }

  condition:
    any of them
}