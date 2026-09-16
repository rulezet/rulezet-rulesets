rule TTP_XOR_QUAD_CurrentVersionRun_9c48 {
  strings:
    $key_9c48 = { cf 27 [2] eb 29 [2] c0 05 [2] ee 27 [2] fa 3c [2] f5 26 [2] eb 3b [2] e9 3a [2] f2 3c [2] ee 3b [2] f2 14 }

  condition:
    any of them
}