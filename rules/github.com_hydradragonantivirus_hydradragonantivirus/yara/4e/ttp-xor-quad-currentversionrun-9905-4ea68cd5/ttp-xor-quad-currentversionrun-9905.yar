rule TTP_XOR_QUAD_CurrentVersionRun_9905 {
  strings:
    $key_9905 = { ca 6a [2] ee 64 [2] c5 48 [2] eb 6a [2] ff 71 [2] f0 6b [2] ee 76 [2] ec 77 [2] f7 71 [2] eb 76 [2] f7 59 }

  condition:
    any of them
}