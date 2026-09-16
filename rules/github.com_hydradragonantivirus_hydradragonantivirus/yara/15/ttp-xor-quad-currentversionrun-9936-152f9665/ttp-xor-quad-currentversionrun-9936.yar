rule TTP_XOR_QUAD_CurrentVersionRun_9936 {
  strings:
    $key_9936 = { ca 59 [2] ee 57 [2] c5 7b [2] eb 59 [2] ff 42 [2] f0 58 [2] ee 45 [2] ec 44 [2] f7 42 [2] eb 45 [2] f7 6a }

  condition:
    any of them
}