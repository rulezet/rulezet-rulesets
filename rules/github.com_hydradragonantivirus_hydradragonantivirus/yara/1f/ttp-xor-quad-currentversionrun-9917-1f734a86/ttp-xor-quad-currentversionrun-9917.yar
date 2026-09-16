rule TTP_XOR_QUAD_CurrentVersionRun_9917 {
  strings:
    $key_9917 = { ca 78 [2] ee 76 [2] c5 5a [2] eb 78 [2] ff 63 [2] f0 79 [2] ee 64 [2] ec 65 [2] f7 63 [2] eb 64 [2] f7 4b }

  condition:
    any of them
}