rule TTP_XOR_QUAD_CurrentVersionRun_873d {
  strings:
    $key_873d = { d4 52 [2] f0 5c [2] db 70 [2] f5 52 [2] e1 49 [2] ee 53 [2] f0 4e [2] f2 4f [2] e9 49 [2] f5 4e [2] e9 61 }

  condition:
    any of them
}