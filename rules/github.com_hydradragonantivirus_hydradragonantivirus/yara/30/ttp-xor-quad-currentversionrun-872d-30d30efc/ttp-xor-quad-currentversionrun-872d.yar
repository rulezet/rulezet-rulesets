rule TTP_XOR_QUAD_CurrentVersionRun_872d {
  strings:
    $key_872d = { d4 42 [2] f0 4c [2] db 60 [2] f5 42 [2] e1 59 [2] ee 43 [2] f0 5e [2] f2 5f [2] e9 59 [2] f5 5e [2] e9 71 }

  condition:
    any of them
}