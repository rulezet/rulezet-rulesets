rule TTP_XOR_QUAD_CurrentVersionRun_8744 {
  strings:
    $key_8744 = { d4 2b [2] f0 25 [2] db 09 [2] f5 2b [2] e1 30 [2] ee 2a [2] f0 37 [2] f2 36 [2] e9 30 [2] f5 37 [2] e9 18 }

  condition:
    any of them
}