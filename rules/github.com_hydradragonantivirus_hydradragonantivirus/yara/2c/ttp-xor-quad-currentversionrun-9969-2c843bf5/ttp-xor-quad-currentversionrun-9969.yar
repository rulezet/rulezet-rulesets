rule TTP_XOR_QUAD_CurrentVersionRun_9969 {
  strings:
    $key_9969 = { ca 06 [2] ee 08 [2] c5 24 [2] eb 06 [2] ff 1d [2] f0 07 [2] ee 1a [2] ec 1b [2] f7 1d [2] eb 1a [2] f7 35 }

  condition:
    any of them
}