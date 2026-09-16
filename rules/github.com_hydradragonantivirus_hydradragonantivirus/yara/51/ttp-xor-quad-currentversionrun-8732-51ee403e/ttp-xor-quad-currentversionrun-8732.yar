rule TTP_XOR_QUAD_CurrentVersionRun_8732 {
  strings:
    $key_8732 = { d4 5d [2] f0 53 [2] db 7f [2] f5 5d [2] e1 46 [2] ee 5c [2] f0 41 [2] f2 40 [2] e9 46 [2] f5 41 [2] e9 6e }

  condition:
    any of them
}