rule TTP_XOR_QUAD_CurrentVersionRun_9c58 {
  strings:
    $key_9c58 = { cf 37 [2] eb 39 [2] c0 15 [2] ee 37 [2] fa 2c [2] f5 36 [2] eb 2b [2] e9 2a [2] f2 2c [2] ee 2b [2] f2 04 }

  condition:
    any of them
}