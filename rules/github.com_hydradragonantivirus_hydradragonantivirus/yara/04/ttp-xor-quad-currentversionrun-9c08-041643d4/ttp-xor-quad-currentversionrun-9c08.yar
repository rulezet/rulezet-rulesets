rule TTP_XOR_QUAD_CurrentVersionRun_9c08 {
  strings:
    $key_9c08 = { cf 67 [2] eb 69 [2] c0 45 [2] ee 67 [2] fa 7c [2] f5 66 [2] eb 7b [2] e9 7a [2] f2 7c [2] ee 7b [2] f2 54 }

  condition:
    any of them
}