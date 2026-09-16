rule TTP_XOR_QUAD_CurrentVersionRun_9942 {
  strings:
    $key_9942 = { ca 2d [2] ee 23 [2] c5 0f [2] eb 2d [2] ff 36 [2] f0 2c [2] ee 31 [2] ec 30 [2] f7 36 [2] eb 31 [2] f7 1e }

  condition:
    any of them
}