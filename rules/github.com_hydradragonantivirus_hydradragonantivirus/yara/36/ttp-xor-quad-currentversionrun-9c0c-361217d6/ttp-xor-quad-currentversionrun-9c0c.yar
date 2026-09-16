rule TTP_XOR_QUAD_CurrentVersionRun_9c0c {
  strings:
    $key_9c0c = { cf 63 [2] eb 6d [2] c0 41 [2] ee 63 [2] fa 78 [2] f5 62 [2] eb 7f [2] e9 7e [2] f2 78 [2] ee 7f [2] f2 50 }

  condition:
    any of them
}