rule TTP_XOR_QUAD_CurrentVersionRun_9717 {
  strings:
    $key_9717 = { c4 78 [2] e0 76 [2] cb 5a [2] e5 78 [2] f1 63 [2] fe 79 [2] e0 64 [2] e2 65 [2] f9 63 [2] e5 64 [2] f9 4b }

  condition:
    any of them
}