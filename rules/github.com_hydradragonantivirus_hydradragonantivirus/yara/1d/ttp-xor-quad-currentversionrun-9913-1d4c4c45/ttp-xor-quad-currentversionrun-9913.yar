rule TTP_XOR_QUAD_CurrentVersionRun_9913 {
  strings:
    $key_9913 = { ca 7c [2] ee 72 [2] c5 5e [2] eb 7c [2] ff 67 [2] f0 7d [2] ee 60 [2] ec 61 [2] f7 67 [2] eb 60 [2] f7 4f }

  condition:
    any of them
}