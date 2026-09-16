rule TTP_XOR_QUAD_CurrentVersionRun_9908 {
  strings:
    $key_9908 = { ca 67 [2] ee 69 [2] c5 45 [2] eb 67 [2] ff 7c [2] f0 66 [2] ee 7b [2] ec 7a [2] f7 7c [2] eb 7b [2] f7 54 }

  condition:
    any of them
}