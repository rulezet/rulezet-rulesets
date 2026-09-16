rule TTP_XOR_QUAD_CurrentVersionRun_9cf3 {
  strings:
    $key_9cf3 = { cf 9c [2] eb 92 [2] c0 be [2] ee 9c [2] fa 87 [2] f5 9d [2] eb 80 [2] e9 81 [2] f2 87 [2] ee 80 [2] f2 af }

  condition:
    any of them
}