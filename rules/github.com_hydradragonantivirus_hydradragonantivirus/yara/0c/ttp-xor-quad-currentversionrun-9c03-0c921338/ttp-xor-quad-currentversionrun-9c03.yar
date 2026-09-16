rule TTP_XOR_QUAD_CurrentVersionRun_9c03 {
  strings:
    $key_9c03 = { cf 6c [2] eb 62 [2] c0 4e [2] ee 6c [2] fa 77 [2] f5 6d [2] eb 70 [2] e9 71 [2] f2 77 [2] ee 70 [2] f2 5f }

  condition:
    any of them
}