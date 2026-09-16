rule TTP_XOR_QUAD_CurrentVersionRun_99f4 {
  strings:
    $key_99f4 = { ca 9b [2] ee 95 [2] c5 b9 [2] eb 9b [2] ff 80 [2] f0 9a [2] ee 87 [2] ec 86 [2] f7 80 [2] eb 87 [2] f7 a8 }

  condition:
    any of them
}