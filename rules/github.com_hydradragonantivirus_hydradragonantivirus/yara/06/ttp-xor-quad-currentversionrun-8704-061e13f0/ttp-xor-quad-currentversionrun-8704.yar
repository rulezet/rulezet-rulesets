rule TTP_XOR_QUAD_CurrentVersionRun_8704 {
  strings:
    $key_8704 = { d4 6b [2] f0 65 [2] db 49 [2] f5 6b [2] e1 70 [2] ee 6a [2] f0 77 [2] f2 76 [2] e9 70 [2] f5 77 [2] e9 58 }

  condition:
    any of them
}