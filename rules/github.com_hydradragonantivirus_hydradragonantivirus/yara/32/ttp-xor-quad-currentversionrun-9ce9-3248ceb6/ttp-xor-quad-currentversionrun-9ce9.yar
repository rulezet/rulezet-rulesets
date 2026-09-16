rule TTP_XOR_QUAD_CurrentVersionRun_9ce9 {
  strings:
    $key_9ce9 = { cf 86 [2] eb 88 [2] c0 a4 [2] ee 86 [2] fa 9d [2] f5 87 [2] eb 9a [2] e9 9b [2] f2 9d [2] ee 9a [2] f2 b5 }

  condition:
    any of them
}