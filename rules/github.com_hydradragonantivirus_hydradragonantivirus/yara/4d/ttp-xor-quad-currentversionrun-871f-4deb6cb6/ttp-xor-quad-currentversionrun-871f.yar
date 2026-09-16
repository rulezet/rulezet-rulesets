rule TTP_XOR_QUAD_CurrentVersionRun_871f {
  strings:
    $key_871f = { d4 70 [2] f0 7e [2] db 52 [2] f5 70 [2] e1 6b [2] ee 71 [2] f0 6c [2] f2 6d [2] e9 6b [2] f5 6c [2] e9 43 }

  condition:
    any of them
}