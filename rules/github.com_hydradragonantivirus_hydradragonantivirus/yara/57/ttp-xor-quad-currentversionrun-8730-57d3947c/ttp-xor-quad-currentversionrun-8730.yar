rule TTP_XOR_QUAD_CurrentVersionRun_8730 {
  strings:
    $key_8730 = { d4 5f [2] f0 51 [2] db 7d [2] f5 5f [2] e1 44 [2] ee 5e [2] f0 43 [2] f2 42 [2] e9 44 [2] f5 43 [2] e9 6c }

  condition:
    any of them
}