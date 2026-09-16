rule TTP_XOR_QUAD_CurrentVersionRun_9c02 {
  strings:
    $key_9c02 = { cf 6d [2] eb 63 [2] c0 4f [2] ee 6d [2] fa 76 [2] f5 6c [2] eb 71 [2] e9 70 [2] f2 76 [2] ee 71 [2] f2 5e }

  condition:
    any of them
}