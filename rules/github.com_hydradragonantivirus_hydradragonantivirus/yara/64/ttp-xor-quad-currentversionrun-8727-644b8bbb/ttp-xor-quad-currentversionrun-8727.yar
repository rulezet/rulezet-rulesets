rule TTP_XOR_QUAD_CurrentVersionRun_8727 {
  strings:
    $key_8727 = { d4 48 [2] f0 46 [2] db 6a [2] f5 48 [2] e1 53 [2] ee 49 [2] f0 54 [2] f2 55 [2] e9 53 [2] f5 54 [2] e9 7b }

  condition:
    any of them
}