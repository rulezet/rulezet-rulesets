rule TTP_XOR_QUAD_CurrentVersionRun_9c06 {
  strings:
    $key_9c06 = { cf 69 [2] eb 67 [2] c0 4b [2] ee 69 [2] fa 72 [2] f5 68 [2] eb 75 [2] e9 74 [2] f2 72 [2] ee 75 [2] f2 5a }

  condition:
    any of them
}