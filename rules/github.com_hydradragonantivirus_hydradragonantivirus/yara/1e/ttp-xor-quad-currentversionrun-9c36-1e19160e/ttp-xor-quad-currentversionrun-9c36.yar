rule TTP_XOR_QUAD_CurrentVersionRun_9c36 {
  strings:
    $key_9c36 = { cf 59 [2] eb 57 [2] c0 7b [2] ee 59 [2] fa 42 [2] f5 58 [2] eb 45 [2] e9 44 [2] f2 42 [2] ee 45 [2] f2 6a }

  condition:
    any of them
}