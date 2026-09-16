rule TTP_XOR_QUAD_CurrentVersionRun_9c18 {
  strings:
    $key_9c18 = { cf 77 [2] eb 79 [2] c0 55 [2] ee 77 [2] fa 6c [2] f5 76 [2] eb 6b [2] e9 6a [2] f2 6c [2] ee 6b [2] f2 44 }

  condition:
    any of them
}