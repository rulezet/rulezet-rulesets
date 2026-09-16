rule TTP_XOR_QUAD_CurrentVersionRun_8716 {
  strings:
    $key_8716 = { d4 79 [2] f0 77 [2] db 5b [2] f5 79 [2] e1 62 [2] ee 78 [2] f0 65 [2] f2 64 [2] e9 62 [2] f5 65 [2] e9 4a }

  condition:
    any of them
}