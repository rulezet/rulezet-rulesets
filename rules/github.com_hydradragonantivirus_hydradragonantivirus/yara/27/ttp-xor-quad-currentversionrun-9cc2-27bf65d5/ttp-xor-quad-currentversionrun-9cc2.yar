rule TTP_XOR_QUAD_CurrentVersionRun_9cc2 {
  strings:
    $key_9cc2 = { cf ad [2] eb a3 [2] c0 8f [2] ee ad [2] fa b6 [2] f5 ac [2] eb b1 [2] e9 b0 [2] f2 b6 [2] ee b1 [2] f2 9e }

  condition:
    any of them
}