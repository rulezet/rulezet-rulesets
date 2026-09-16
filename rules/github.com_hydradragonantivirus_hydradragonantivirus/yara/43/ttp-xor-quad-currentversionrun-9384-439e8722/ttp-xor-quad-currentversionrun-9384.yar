rule TTP_XOR_QUAD_CurrentVersionRun_9384 {
  strings:
    $key_9384 = { c0 eb [2] e4 e5 [2] cf c9 [2] e1 eb [2] f5 f0 [2] fa ea [2] e4 f7 [2] e6 f6 [2] fd f0 [2] e1 f7 [2] fd d8 }

  condition:
    any of them
}