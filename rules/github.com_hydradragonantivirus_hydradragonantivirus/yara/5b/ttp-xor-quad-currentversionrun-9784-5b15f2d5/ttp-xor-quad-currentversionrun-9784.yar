rule TTP_XOR_QUAD_CurrentVersionRun_9784 {
  strings:
    $key_9784 = { c4 eb [2] e0 e5 [2] cb c9 [2] e5 eb [2] f1 f0 [2] fe ea [2] e0 f7 [2] e2 f6 [2] f9 f0 [2] e5 f7 [2] f9 d8 }

  condition:
    any of them
}