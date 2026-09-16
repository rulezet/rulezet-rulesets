rule TTP_XOR_QUAD_CurrentVersionRun_99e9 {
  strings:
    $key_99e9 = { ca 86 [2] ee 88 [2] c5 a4 [2] eb 86 [2] ff 9d [2] f0 87 [2] ee 9a [2] ec 9b [2] f7 9d [2] eb 9a [2] f7 b5 }

  condition:
    any of them
}