rule TTP_XOR_QUAD_CurrentVersionRun_9c76 {
  strings:
    $key_9c76 = { cf 19 [2] eb 17 [2] c0 3b [2] ee 19 [2] fa 02 [2] f5 18 [2] eb 05 [2] e9 04 [2] f2 02 [2] ee 05 [2] f2 2a }

  condition:
    any of them
}