rule TTP_XOR_QUAD_CurrentVersionRun_9904 {
  strings:
    $key_9904 = { ca 6b [2] ee 65 [2] c5 49 [2] eb 6b [2] ff 70 [2] f0 6a [2] ee 77 [2] ec 76 [2] f7 70 [2] eb 77 [2] f7 58 }

  condition:
    any of them
}