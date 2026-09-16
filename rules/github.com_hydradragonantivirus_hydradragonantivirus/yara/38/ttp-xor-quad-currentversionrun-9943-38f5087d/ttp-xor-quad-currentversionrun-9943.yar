rule TTP_XOR_QUAD_CurrentVersionRun_9943 {
  strings:
    $key_9943 = { ca 2c [2] ee 22 [2] c5 0e [2] eb 2c [2] ff 37 [2] f0 2d [2] ee 30 [2] ec 31 [2] f7 37 [2] eb 30 [2] f7 1f }

  condition:
    any of them
}