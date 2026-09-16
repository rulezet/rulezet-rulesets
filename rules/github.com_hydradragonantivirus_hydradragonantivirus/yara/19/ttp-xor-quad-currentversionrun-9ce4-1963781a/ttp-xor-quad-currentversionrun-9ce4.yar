rule TTP_XOR_QUAD_CurrentVersionRun_9ce4 {
  strings:
    $key_9ce4 = { cf 8b [2] eb 85 [2] c0 a9 [2] ee 8b [2] fa 90 [2] f5 8a [2] eb 97 [2] e9 96 [2] f2 90 [2] ee 97 [2] f2 b8 }

  condition:
    any of them
}