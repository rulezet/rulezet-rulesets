rule TTP_XOR_QUAD_CurrentVersionRun_9925 {
  strings:
    $key_9925 = { ca 4a [2] ee 44 [2] c5 68 [2] eb 4a [2] ff 51 [2] f0 4b [2] ee 56 [2] ec 57 [2] f7 51 [2] eb 56 [2] f7 79 }

  condition:
    any of them
}