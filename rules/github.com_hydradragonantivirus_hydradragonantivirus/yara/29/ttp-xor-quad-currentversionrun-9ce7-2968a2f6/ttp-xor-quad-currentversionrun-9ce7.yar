rule TTP_XOR_QUAD_CurrentVersionRun_9ce7 {
  strings:
    $key_9ce7 = { cf 88 [2] eb 86 [2] c0 aa [2] ee 88 [2] fa 93 [2] f5 89 [2] eb 94 [2] e9 95 [2] f2 93 [2] ee 94 [2] f2 bb }

  condition:
    any of them
}