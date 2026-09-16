rule TTP_XOR_QUAD_CurrentVersionRun_9785 {
  strings:
    $key_9785 = { c4 ea [2] e0 e4 [2] cb c8 [2] e5 ea [2] f1 f1 [2] fe eb [2] e0 f6 [2] e2 f7 [2] f9 f1 [2] e5 f6 [2] f9 d9 }

  condition:
    any of them
}