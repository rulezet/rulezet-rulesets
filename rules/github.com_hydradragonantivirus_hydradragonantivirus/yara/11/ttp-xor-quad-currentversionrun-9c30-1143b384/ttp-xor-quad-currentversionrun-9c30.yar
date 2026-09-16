rule TTP_XOR_QUAD_CurrentVersionRun_9c30 {
  strings:
    $key_9c30 = { cf 5f [2] eb 51 [2] c0 7d [2] ee 5f [2] fa 44 [2] f5 5e [2] eb 43 [2] e9 42 [2] f2 44 [2] ee 43 [2] f2 6c }

  condition:
    any of them
}