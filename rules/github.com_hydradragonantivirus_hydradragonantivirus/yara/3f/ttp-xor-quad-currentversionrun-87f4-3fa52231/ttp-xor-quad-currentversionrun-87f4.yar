rule TTP_XOR_QUAD_CurrentVersionRun_87f4 {
  strings:
    $key_87f4 = { d4 9b [2] f0 95 [2] db b9 [2] f5 9b [2] e1 80 [2] ee 9a [2] f0 87 [2] f2 86 [2] e9 80 [2] f5 87 [2] e9 a8 }

  condition:
    any of them
}