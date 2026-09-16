rule TTP_XOR_QUAD_CurrentVersionRun_9923 {
  strings:
    $key_9923 = { ca 4c [2] ee 42 [2] c5 6e [2] eb 4c [2] ff 57 [2] f0 4d [2] ee 50 [2] ec 51 [2] f7 57 [2] eb 50 [2] f7 7f }

  condition:
    any of them
}