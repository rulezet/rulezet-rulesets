rule TTP_XOR_QUAD_CurrentVersionRun_9c79 {
  strings:
    $key_9c79 = { cf 16 [2] eb 18 [2] c0 34 [2] ee 16 [2] fa 0d [2] f5 17 [2] eb 0a [2] e9 0b [2] f2 0d [2] ee 0a [2] f2 25 }

  condition:
    any of them
}