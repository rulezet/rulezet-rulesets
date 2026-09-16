rule TTP_XOR_QUAD_CurrentVersionRun_87f9 {
  strings:
    $key_87f9 = { d4 96 [2] f0 98 [2] db b4 [2] f5 96 [2] e1 8d [2] ee 97 [2] f0 8a [2] f2 8b [2] e9 8d [2] f5 8a [2] e9 a5 }

  condition:
    any of them
}