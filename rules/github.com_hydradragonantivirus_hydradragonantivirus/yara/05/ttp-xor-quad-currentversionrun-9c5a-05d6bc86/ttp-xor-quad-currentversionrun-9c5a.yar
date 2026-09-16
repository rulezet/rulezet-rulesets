rule TTP_XOR_QUAD_CurrentVersionRun_9c5a {
  strings:
    $key_9c5a = { cf 35 [2] eb 3b [2] c0 17 [2] ee 35 [2] fa 2e [2] f5 34 [2] eb 29 [2] e9 28 [2] f2 2e [2] ee 29 [2] f2 06 }

  condition:
    any of them
}