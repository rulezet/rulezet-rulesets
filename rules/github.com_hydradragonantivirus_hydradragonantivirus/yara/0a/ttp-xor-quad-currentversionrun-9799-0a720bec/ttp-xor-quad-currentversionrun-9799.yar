rule TTP_XOR_QUAD_CurrentVersionRun_9799 {
  strings:
    $key_9799 = { c4 f6 [2] e0 f8 [2] cb d4 [2] e5 f6 [2] f1 ed [2] fe f7 [2] e0 ea [2] e2 eb [2] f9 ed [2] e5 ea [2] f9 c5 }

  condition:
    any of them
}