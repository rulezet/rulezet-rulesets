rule TTP_XOR_QUAD_CurrentVersionRun_9c54 {
  strings:
    $key_9c54 = { cf 3b [2] eb 35 [2] c0 19 [2] ee 3b [2] fa 20 [2] f5 3a [2] eb 27 [2] e9 26 [2] f2 20 [2] ee 27 [2] f2 08 }

  condition:
    any of them
}