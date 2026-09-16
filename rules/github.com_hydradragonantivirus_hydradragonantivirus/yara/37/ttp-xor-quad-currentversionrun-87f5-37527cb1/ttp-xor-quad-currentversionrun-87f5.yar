rule TTP_XOR_QUAD_CurrentVersionRun_87f5 {
  strings:
    $key_87f5 = { d4 9a [2] f0 94 [2] db b8 [2] f5 9a [2] e1 81 [2] ee 9b [2] f0 86 [2] f2 87 [2] e9 81 [2] f5 86 [2] e9 a9 }

  condition:
    any of them
}