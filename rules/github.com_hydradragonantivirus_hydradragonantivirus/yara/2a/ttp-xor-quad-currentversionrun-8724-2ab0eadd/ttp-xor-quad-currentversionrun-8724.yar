rule TTP_XOR_QUAD_CurrentVersionRun_8724 {
  strings:
    $key_8724 = { d4 4b [2] f0 45 [2] db 69 [2] f5 4b [2] e1 50 [2] ee 4a [2] f0 57 [2] f2 56 [2] e9 50 [2] f5 57 [2] e9 78 }

  condition:
    any of them
}