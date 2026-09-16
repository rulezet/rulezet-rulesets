rule TTP_XOR_QUAD_CurrentVersionRun_9734 {
  strings:
    $key_9734 = { c4 5b [2] e0 55 [2] cb 79 [2] e5 5b [2] f1 40 [2] fe 5a [2] e0 47 [2] e2 46 [2] f9 40 [2] e5 47 [2] f9 68 }

  condition:
    any of them
}