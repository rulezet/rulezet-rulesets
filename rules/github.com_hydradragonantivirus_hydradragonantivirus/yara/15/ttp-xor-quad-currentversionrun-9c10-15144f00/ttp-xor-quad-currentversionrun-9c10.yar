rule TTP_XOR_QUAD_CurrentVersionRun_9c10 {
  strings:
    $key_9c10 = { cf 7f [2] eb 71 [2] c0 5d [2] ee 7f [2] fa 64 [2] f5 7e [2] eb 63 [2] e9 62 [2] f2 64 [2] ee 63 [2] f2 4c }

  condition:
    any of them
}