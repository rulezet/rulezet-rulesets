rule TTP_XOR_QUAD_CurrentVersionRun_9724 {
  strings:
    $key_9724 = { c4 4b [2] e0 45 [2] cb 69 [2] e5 4b [2] f1 50 [2] fe 4a [2] e0 57 [2] e2 56 [2] f9 50 [2] e5 57 [2] f9 78 }

  condition:
    any of them
}