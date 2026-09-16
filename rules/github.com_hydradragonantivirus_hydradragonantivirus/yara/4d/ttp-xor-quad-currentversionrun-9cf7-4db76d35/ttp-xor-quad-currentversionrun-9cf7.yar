rule TTP_XOR_QUAD_CurrentVersionRun_9cf7 {
  strings:
    $key_9cf7 = { cf 98 [2] eb 96 [2] c0 ba [2] ee 98 [2] fa 83 [2] f5 99 [2] eb 84 [2] e9 85 [2] f2 83 [2] ee 84 [2] f2 ab }

  condition:
    any of them
}