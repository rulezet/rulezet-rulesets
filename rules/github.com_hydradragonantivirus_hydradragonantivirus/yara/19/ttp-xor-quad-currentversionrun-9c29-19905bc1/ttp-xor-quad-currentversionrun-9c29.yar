rule TTP_XOR_QUAD_CurrentVersionRun_9c29 {
  strings:
    $key_9c29 = { cf 46 [2] eb 48 [2] c0 64 [2] ee 46 [2] fa 5d [2] f5 47 [2] eb 5a [2] e9 5b [2] f2 5d [2] ee 5a [2] f2 75 }

  condition:
    any of them
}