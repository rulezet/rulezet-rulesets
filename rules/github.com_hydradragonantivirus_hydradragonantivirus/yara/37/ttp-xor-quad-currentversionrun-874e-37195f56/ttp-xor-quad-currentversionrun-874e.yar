rule TTP_XOR_QUAD_CurrentVersionRun_874e {
  strings:
    $key_874e = { d4 21 [2] f0 2f [2] db 03 [2] f5 21 [2] e1 3a [2] ee 20 [2] f0 3d [2] f2 3c [2] e9 3a [2] f5 3d [2] e9 12 }

  condition:
    any of them
}