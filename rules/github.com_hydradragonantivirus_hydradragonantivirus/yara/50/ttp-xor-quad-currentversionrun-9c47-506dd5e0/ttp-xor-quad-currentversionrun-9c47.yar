rule TTP_XOR_QUAD_CurrentVersionRun_9c47 {
  strings:
    $key_9c47 = { cf 28 [2] eb 26 [2] c0 0a [2] ee 28 [2] fa 33 [2] f5 29 [2] eb 34 [2] e9 35 [2] f2 33 [2] ee 34 [2] f2 1b }

  condition:
    any of them
}