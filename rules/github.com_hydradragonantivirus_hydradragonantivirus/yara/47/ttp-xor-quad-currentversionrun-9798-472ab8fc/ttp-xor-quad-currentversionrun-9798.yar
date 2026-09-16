rule TTP_XOR_QUAD_CurrentVersionRun_9798 {
  strings:
    $key_9798 = { c4 f7 [2] e0 f9 [2] cb d5 [2] e5 f7 [2] f1 ec [2] fe f6 [2] e0 eb [2] e2 ea [2] f9 ec [2] e5 eb [2] f9 c4 }

  condition:
    any of them
}