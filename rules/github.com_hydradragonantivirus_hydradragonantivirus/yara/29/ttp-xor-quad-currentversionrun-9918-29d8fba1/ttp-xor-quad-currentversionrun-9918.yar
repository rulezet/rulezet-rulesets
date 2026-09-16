rule TTP_XOR_QUAD_CurrentVersionRun_9918 {
  strings:
    $key_9918 = { ca 77 [2] ee 79 [2] c5 55 [2] eb 77 [2] ff 6c [2] f0 76 [2] ee 6b [2] ec 6a [2] f7 6c [2] eb 6b [2] f7 44 }

  condition:
    any of them
}