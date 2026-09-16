rule TTP_XOR_QUAD_CurrentVersionRun_9cc3 {
  strings:
    $key_9cc3 = { cf ac [2] eb a2 [2] c0 8e [2] ee ac [2] fa b7 [2] f5 ad [2] eb b0 [2] e9 b1 [2] f2 b7 [2] ee b0 [2] f2 9f }

  condition:
    any of them
}