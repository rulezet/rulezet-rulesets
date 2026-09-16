rule TTP_XOR_QUAD_CurrentVersionRun_9965 {
  strings:
    $key_9965 = { ca 0a [2] ee 04 [2] c5 28 [2] eb 0a [2] ff 11 [2] f0 0b [2] ee 16 [2] ec 17 [2] f7 11 [2] eb 16 [2] f7 39 }

  condition:
    any of them
}