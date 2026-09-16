rule TTP_XOR_QUAD_CurrentVersionRun_8778 {
  strings:
    $key_8778 = { d4 17 [2] f0 19 [2] db 35 [2] f5 17 [2] e1 0c [2] ee 16 [2] f0 0b [2] f2 0a [2] e9 0c [2] f5 0b [2] e9 24 }

  condition:
    any of them
}