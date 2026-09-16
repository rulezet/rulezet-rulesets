rule TTP_XOR_QUAD_CurrentVersionRun_9966 {
  strings:
    $key_9966 = { ca 09 [2] ee 07 [2] c5 2b [2] eb 09 [2] ff 12 [2] f0 08 [2] ee 15 [2] ec 14 [2] f7 12 [2] eb 15 [2] f7 3a }

  condition:
    any of them
}