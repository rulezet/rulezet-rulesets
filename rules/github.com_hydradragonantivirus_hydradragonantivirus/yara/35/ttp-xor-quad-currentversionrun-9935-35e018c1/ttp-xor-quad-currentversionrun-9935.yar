rule TTP_XOR_QUAD_CurrentVersionRun_9935 {
  strings:
    $key_9935 = { ca 5a [2] ee 54 [2] c5 78 [2] eb 5a [2] ff 41 [2] f0 5b [2] ee 46 [2] ec 47 [2] f7 41 [2] eb 46 [2] f7 69 }

  condition:
    any of them
}