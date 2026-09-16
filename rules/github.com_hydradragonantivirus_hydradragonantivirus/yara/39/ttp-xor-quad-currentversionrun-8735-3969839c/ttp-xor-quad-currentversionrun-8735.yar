rule TTP_XOR_QUAD_CurrentVersionRun_8735 {
  strings:
    $key_8735 = { d4 5a [2] f0 54 [2] db 78 [2] f5 5a [2] e1 41 [2] ee 5b [2] f0 46 [2] f2 47 [2] e9 41 [2] f5 46 [2] e9 69 }

  condition:
    any of them
}