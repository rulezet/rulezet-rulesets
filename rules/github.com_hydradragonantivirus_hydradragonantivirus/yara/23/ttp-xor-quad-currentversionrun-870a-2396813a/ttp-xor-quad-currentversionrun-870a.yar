rule TTP_XOR_QUAD_CurrentVersionRun_870a {
  strings:
    $key_870a = { d4 65 [2] f0 6b [2] db 47 [2] f5 65 [2] e1 7e [2] ee 64 [2] f0 79 [2] f2 78 [2] e9 7e [2] f5 79 [2] e9 56 }

  condition:
    any of them
}