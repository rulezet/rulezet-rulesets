rule TTP_XOR_QUAD_CurrentVersionRun_9ce6 {
  strings:
    $key_9ce6 = { cf 89 [2] eb 87 [2] c0 ab [2] ee 89 [2] fa 92 [2] f5 88 [2] eb 95 [2] e9 94 [2] f2 92 [2] ee 95 [2] f2 ba }

  condition:
    any of them
}