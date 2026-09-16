rule TTP_XOR_QUAD_CurrentVersionRun_9957 {
  strings:
    $key_9957 = { ca 38 [2] ee 36 [2] c5 1a [2] eb 38 [2] ff 23 [2] f0 39 [2] ee 24 [2] ec 25 [2] f7 23 [2] eb 24 [2] f7 0b }

  condition:
    any of them
}