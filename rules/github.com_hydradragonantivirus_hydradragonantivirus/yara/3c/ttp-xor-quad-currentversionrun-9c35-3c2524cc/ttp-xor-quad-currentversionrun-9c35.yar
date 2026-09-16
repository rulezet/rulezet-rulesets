rule TTP_XOR_QUAD_CurrentVersionRun_9c35 {
  strings:
    $key_9c35 = { cf 5a [2] eb 54 [2] c0 78 [2] ee 5a [2] fa 41 [2] f5 5b [2] eb 46 [2] e9 47 [2] f2 41 [2] ee 46 [2] f2 69 }

  condition:
    any of them
}