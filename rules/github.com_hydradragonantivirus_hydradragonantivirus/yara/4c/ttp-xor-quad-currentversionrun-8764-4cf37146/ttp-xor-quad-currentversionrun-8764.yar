rule TTP_XOR_QUAD_CurrentVersionRun_8764 {
  strings:
    $key_8764 = { d4 0b [2] f0 05 [2] db 29 [2] f5 0b [2] e1 10 [2] ee 0a [2] f0 17 [2] f2 16 [2] e9 10 [2] f5 17 [2] e9 38 }

  condition:
    any of them
}