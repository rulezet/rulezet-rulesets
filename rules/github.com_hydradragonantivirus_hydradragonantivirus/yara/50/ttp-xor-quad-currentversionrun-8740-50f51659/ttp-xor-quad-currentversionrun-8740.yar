rule TTP_XOR_QUAD_CurrentVersionRun_8740 {
  strings:
    $key_8740 = { d4 2f [2] f0 21 [2] db 0d [2] f5 2f [2] e1 34 [2] ee 2e [2] f0 33 [2] f2 32 [2] e9 34 [2] f5 33 [2] e9 1c }

  condition:
    any of them
}