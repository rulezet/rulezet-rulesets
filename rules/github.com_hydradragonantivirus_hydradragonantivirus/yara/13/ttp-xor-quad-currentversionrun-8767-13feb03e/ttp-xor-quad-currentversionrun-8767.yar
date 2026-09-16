rule TTP_XOR_QUAD_CurrentVersionRun_8767 {
  strings:
    $key_8767 = { d4 08 [2] f0 06 [2] db 2a [2] f5 08 [2] e1 13 [2] ee 09 [2] f0 14 [2] f2 15 [2] e9 13 [2] f5 14 [2] e9 3b }

  condition:
    any of them
}