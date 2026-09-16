rule TTP_XOR_QUAD_CurrentVersionRun_9c63 {
  strings:
    $key_9c63 = { cf 0c [2] eb 02 [2] c0 2e [2] ee 0c [2] fa 17 [2] f5 0d [2] eb 10 [2] e9 11 [2] f2 17 [2] ee 10 [2] f2 3f }

  condition:
    any of them
}