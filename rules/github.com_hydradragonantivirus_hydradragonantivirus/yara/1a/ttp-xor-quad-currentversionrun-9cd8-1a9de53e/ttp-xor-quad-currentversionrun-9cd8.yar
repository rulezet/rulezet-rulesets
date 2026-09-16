rule TTP_XOR_QUAD_CurrentVersionRun_9cd8 {
  strings:
    $key_9cd8 = { cf b7 [2] eb b9 [2] c0 95 [2] ee b7 [2] fa ac [2] f5 b6 [2] eb ab [2] e9 aa [2] f2 ac [2] ee ab [2] f2 84 }

  condition:
    any of them
}