rule TTP_XOR_QUAD_CurrentVersionRun_9c17 {
  strings:
    $key_9c17 = { cf 78 [2] eb 76 [2] c0 5a [2] ee 78 [2] fa 63 [2] f5 79 [2] eb 64 [2] e9 65 [2] f2 63 [2] ee 64 [2] f2 4b }

  condition:
    any of them
}