rule TTP_XOR_QUAD_CurrentVersionRun_9585 {
  strings:
    $key_9585 = { c6 ea [2] e2 e4 [2] c9 c8 [2] e7 ea [2] f3 f1 [2] fc eb [2] e2 f6 [2] e0 f7 [2] fb f1 [2] e7 f6 [2] fb d9 }

  condition:
    any of them
}