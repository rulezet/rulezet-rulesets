rule TTP_XOR_QUAD_CurrentVersionRun_9956 {
  strings:
    $key_9956 = { ca 39 [2] ee 37 [2] c5 1b [2] eb 39 [2] ff 22 [2] f0 38 [2] ee 25 [2] ec 24 [2] f7 22 [2] eb 25 [2] f7 0a }

  condition:
    any of them
}