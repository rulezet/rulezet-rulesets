rule TTP_XOR_QUAD_CurrentVersionRun_9757 {
  strings:
    $key_9757 = { c4 38 [2] e0 36 [2] cb 1a [2] e5 38 [2] f1 23 [2] fe 39 [2] e0 24 [2] e2 25 [2] f9 23 [2] e5 24 [2] f9 0b }

  condition:
    any of them
}