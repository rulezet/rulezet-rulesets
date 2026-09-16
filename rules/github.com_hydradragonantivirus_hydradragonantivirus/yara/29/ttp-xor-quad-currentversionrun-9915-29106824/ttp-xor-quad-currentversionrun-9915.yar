rule TTP_XOR_QUAD_CurrentVersionRun_9915 {
  strings:
    $key_9915 = { ca 7a [2] ee 74 [2] c5 58 [2] eb 7a [2] ff 61 [2] f0 7b [2] ee 66 [2] ec 67 [2] f7 61 [2] eb 66 [2] f7 49 }

  condition:
    any of them
}