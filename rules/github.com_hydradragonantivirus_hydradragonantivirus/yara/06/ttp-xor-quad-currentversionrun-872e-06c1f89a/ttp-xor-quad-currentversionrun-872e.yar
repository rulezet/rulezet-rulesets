rule TTP_XOR_QUAD_CurrentVersionRun_872e {
  strings:
    $key_872e = { d4 41 [2] f0 4f [2] db 63 [2] f5 41 [2] e1 5a [2] ee 40 [2] f0 5d [2] f2 5c [2] e9 5a [2] f5 5d [2] e9 72 }

  condition:
    any of them
}