rule TTP_XOR_QUAD_CurrentVersionRun_9ce1 {
  strings:
    $key_9ce1 = { cf 8e [2] eb 80 [2] c0 ac [2] ee 8e [2] fa 95 [2] f5 8f [2] eb 92 [2] e9 93 [2] f2 95 [2] ee 92 [2] f2 bd }

  condition:
    any of them
}