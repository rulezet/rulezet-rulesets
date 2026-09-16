rule TTP_XOR_QUAD_CurrentVersionRun_875a {
  strings:
    $key_875a = { d4 35 [2] f0 3b [2] db 17 [2] f5 35 [2] e1 2e [2] ee 34 [2] f0 29 [2] f2 28 [2] e9 2e [2] f5 29 [2] e9 06 }

  condition:
    any of them
}