rule TTP_XOR_QUAD_CurrentVersionRun_8758 {
  strings:
    $key_8758 = { d4 37 [2] f0 39 [2] db 15 [2] f5 37 [2] e1 2c [2] ee 36 [2] f0 2b [2] f2 2a [2] e9 2c [2] f5 2b [2] e9 04 }

  condition:
    any of them
}