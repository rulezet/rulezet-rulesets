rule TTP_XOR_QUAD_CurrentVersionRun_9c07 {
  strings:
    $key_9c07 = { cf 68 [2] eb 66 [2] c0 4a [2] ee 68 [2] fa 73 [2] f5 69 [2] eb 74 [2] e9 75 [2] f2 73 [2] ee 74 [2] f2 5b }

  condition:
    any of them
}