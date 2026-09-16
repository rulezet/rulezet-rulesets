rule TTP_XOR_QUAD_CurrentVersionRun_9c20 {
  strings:
    $key_9c20 = { cf 4f [2] eb 41 [2] c0 6d [2] ee 4f [2] fa 54 [2] f5 4e [2] eb 53 [2] e9 52 [2] f2 54 [2] ee 53 [2] f2 7c }

  condition:
    any of them
}