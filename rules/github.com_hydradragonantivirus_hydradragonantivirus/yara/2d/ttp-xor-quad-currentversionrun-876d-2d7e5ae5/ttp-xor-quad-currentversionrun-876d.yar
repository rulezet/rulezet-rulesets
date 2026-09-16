rule TTP_XOR_QUAD_CurrentVersionRun_876d {
  strings:
    $key_876d = { d4 02 [2] f0 0c [2] db 20 [2] f5 02 [2] e1 19 [2] ee 03 [2] f0 1e [2] f2 1f [2] e9 19 [2] f5 1e [2] e9 31 }

  condition:
    any of them
}