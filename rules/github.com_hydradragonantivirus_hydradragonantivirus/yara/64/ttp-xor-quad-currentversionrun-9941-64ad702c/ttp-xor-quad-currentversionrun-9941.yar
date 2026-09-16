rule TTP_XOR_QUAD_CurrentVersionRun_9941 {
  strings:
    $key_9941 = { ca 2e [2] ee 20 [2] c5 0c [2] eb 2e [2] ff 35 [2] f0 2f [2] ee 32 [2] ec 33 [2] f7 35 [2] eb 32 [2] f7 1d }

  condition:
    any of them
}