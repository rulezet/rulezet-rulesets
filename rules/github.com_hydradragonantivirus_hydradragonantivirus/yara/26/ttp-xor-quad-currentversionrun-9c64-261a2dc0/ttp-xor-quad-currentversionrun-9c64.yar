rule TTP_XOR_QUAD_CurrentVersionRun_9c64 {
  strings:
    $key_9c64 = { cf 0b [2] eb 05 [2] c0 29 [2] ee 0b [2] fa 10 [2] f5 0a [2] eb 17 [2] e9 16 [2] f2 10 [2] ee 17 [2] f2 38 }

  condition:
    any of them
}