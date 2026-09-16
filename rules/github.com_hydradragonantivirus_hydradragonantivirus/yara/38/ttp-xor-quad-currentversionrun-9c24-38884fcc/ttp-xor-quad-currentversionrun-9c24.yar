rule TTP_XOR_QUAD_CurrentVersionRun_9c24 {
  strings:
    $key_9c24 = { cf 4b [2] eb 45 [2] c0 69 [2] ee 4b [2] fa 50 [2] f5 4a [2] eb 57 [2] e9 56 [2] f2 50 [2] ee 57 [2] f2 78 }

  condition:
    any of them
}