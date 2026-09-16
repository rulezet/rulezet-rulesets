rule TTP_XOR_QUAD_CurrentVersionRun_9975 {
  strings:
    $key_9975 = { ca 1a [2] ee 14 [2] c5 38 [2] eb 1a [2] ff 01 [2] f0 1b [2] ee 06 [2] ec 07 [2] f7 01 [2] eb 06 [2] f7 29 }

  condition:
    any of them
}