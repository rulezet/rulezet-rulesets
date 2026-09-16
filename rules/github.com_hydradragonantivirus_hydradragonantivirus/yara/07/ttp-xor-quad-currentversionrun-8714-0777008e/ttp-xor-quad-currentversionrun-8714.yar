rule TTP_XOR_QUAD_CurrentVersionRun_8714 {
  strings:
    $key_8714 = { d4 7b [2] f0 75 [2] db 59 [2] f5 7b [2] e1 60 [2] ee 7a [2] f0 67 [2] f2 66 [2] e9 60 [2] f5 67 [2] e9 48 }

  condition:
    any of them
}