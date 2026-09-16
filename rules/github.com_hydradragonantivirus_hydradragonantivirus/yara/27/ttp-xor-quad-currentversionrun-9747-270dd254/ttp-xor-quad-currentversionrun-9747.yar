rule TTP_XOR_QUAD_CurrentVersionRun_9747 {
  strings:
    $key_9747 = { c4 28 [2] e0 26 [2] cb 0a [2] e5 28 [2] f1 33 [2] fe 29 [2] e0 34 [2] e2 35 [2] f9 33 [2] e5 34 [2] f9 1b }

  condition:
    any of them
}