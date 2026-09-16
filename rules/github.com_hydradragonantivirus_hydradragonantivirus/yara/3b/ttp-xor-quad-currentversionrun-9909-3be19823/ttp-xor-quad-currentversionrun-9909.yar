rule TTP_XOR_QUAD_CurrentVersionRun_9909 {
  strings:
    $key_9909 = { ca 66 [2] ee 68 [2] c5 44 [2] eb 66 [2] ff 7d [2] f0 67 [2] ee 7a [2] ec 7b [2] f7 7d [2] eb 7a [2] f7 55 }

  condition:
    any of them
}