rule TTP_XOR_QUAD_CurrentVersionRun_9978 {
  strings:
    $key_9978 = { ca 17 [2] ee 19 [2] c5 35 [2] eb 17 [2] ff 0c [2] f0 16 [2] ee 0b [2] ec 0a [2] f7 0c [2] eb 0b [2] f7 24 }

  condition:
    any of them
}