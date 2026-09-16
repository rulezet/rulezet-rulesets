rule TTP_XOR_QUAD_CurrentVersionRun_8739 {
  strings:
    $key_8739 = { d4 56 [2] f0 58 [2] db 74 [2] f5 56 [2] e1 4d [2] ee 57 [2] f0 4a [2] f2 4b [2] e9 4d [2] f5 4a [2] e9 65 }

  condition:
    any of them
}