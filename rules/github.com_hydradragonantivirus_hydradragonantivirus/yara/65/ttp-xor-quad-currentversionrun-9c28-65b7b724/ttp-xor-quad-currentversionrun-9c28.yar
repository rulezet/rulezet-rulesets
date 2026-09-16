rule TTP_XOR_QUAD_CurrentVersionRun_9c28 {
  strings:
    $key_9c28 = { cf 47 [2] eb 49 [2] c0 65 [2] ee 47 [2] fa 5c [2] f5 46 [2] eb 5b [2] e9 5a [2] f2 5c [2] ee 5b [2] f2 74 }

  condition:
    any of them
}