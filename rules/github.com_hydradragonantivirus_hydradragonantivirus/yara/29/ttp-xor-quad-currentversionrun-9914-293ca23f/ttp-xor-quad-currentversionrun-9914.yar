rule TTP_XOR_QUAD_CurrentVersionRun_9914 {
  strings:
    $key_9914 = { ca 7b [2] ee 75 [2] c5 59 [2] eb 7b [2] ff 60 [2] f0 7a [2] ee 67 [2] ec 66 [2] f7 60 [2] eb 67 [2] f7 48 }

  condition:
    any of them
}