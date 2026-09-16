rule TTP_XOR_QUAD_CurrentVersionRun_9ce2 {
  strings:
    $key_9ce2 = { cf 8d [2] eb 83 [2] c0 af [2] ee 8d [2] fa 96 [2] f5 8c [2] eb 91 [2] e9 90 [2] f2 96 [2] ee 91 [2] f2 be }

  condition:
    any of them
}