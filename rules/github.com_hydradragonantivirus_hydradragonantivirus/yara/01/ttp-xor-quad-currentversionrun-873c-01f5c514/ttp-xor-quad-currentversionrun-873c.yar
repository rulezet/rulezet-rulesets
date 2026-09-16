rule TTP_XOR_QUAD_CurrentVersionRun_873c {
  strings:
    $key_873c = { d4 53 [2] f0 5d [2] db 71 [2] f5 53 [2] e1 48 [2] ee 52 [2] f0 4f [2] f2 4e [2] e9 48 [2] f5 4f [2] e9 60 }

  condition:
    any of them
}