rule TTP_XOR_QUAD_CurrentVersionRun_870c {
  strings:
    $key_870c = { d4 63 [2] f0 6d [2] db 41 [2] f5 63 [2] e1 78 [2] ee 62 [2] f0 7f [2] f2 7e [2] e9 78 [2] f5 7f [2] e9 50 }

  condition:
    any of them
}