rule TTP_XOR_QUAD_CurrentVersionRun_99f9 {
  strings:
    $key_99f9 = { ca 96 [2] ee 98 [2] c5 b4 [2] eb 96 [2] ff 8d [2] f0 97 [2] ee 8a [2] ec 8b [2] f7 8d [2] eb 8a [2] f7 a5 }

  condition:
    any of them
}