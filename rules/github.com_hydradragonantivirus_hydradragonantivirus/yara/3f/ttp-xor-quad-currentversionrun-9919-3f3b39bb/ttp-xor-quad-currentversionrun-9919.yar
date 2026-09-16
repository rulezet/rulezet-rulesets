rule TTP_XOR_QUAD_CurrentVersionRun_9919 {
  strings:
    $key_9919 = { ca 76 [2] ee 78 [2] c5 54 [2] eb 76 [2] ff 6d [2] f0 77 [2] ee 6a [2] ec 6b [2] f7 6d [2] eb 6a [2] f7 45 }

  condition:
    any of them
}