rule TTP_XOR_QUAD_CurrentVersionRun_871d {
  strings:
    $key_871d = { d4 72 [2] f0 7c [2] db 50 [2] f5 72 [2] e1 69 [2] ee 73 [2] f0 6e [2] f2 6f [2] e9 69 [2] f5 6e [2] e9 41 }

  condition:
    any of them
}