rule TTP_XOR_QUAD_CurrentVersionRun_8705 {
  strings:
    $key_8705 = { d4 6a [2] f0 64 [2] db 48 [2] f5 6a [2] e1 71 [2] ee 6b [2] f0 76 [2] f2 77 [2] e9 71 [2] f5 76 [2] e9 59 }

  condition:
    any of them
}