rule TTP_XOR_QUAD_CurrentVersionRun_9727 {
  strings:
    $key_9727 = { c4 48 [2] e0 46 [2] cb 6a [2] e5 48 [2] f1 53 [2] fe 49 [2] e0 54 [2] e2 55 [2] f9 53 [2] e5 54 [2] f9 7b }

  condition:
    any of them
}