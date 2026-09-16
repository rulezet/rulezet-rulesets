rule TTP_XOR_QUAD_CurrentVersionRun_9927 {
  strings:
    $key_9927 = { ca 48 [2] ee 46 [2] c5 6a [2] eb 48 [2] ff 53 [2] f0 49 [2] ee 54 [2] ec 55 [2] f7 53 [2] eb 54 [2] f7 7b }

  condition:
    any of them
}