rule TTP_XOR_QUAD_CurrentVersionRun_9705 {
  strings:
    $key_9705 = { c4 6a [2] e0 64 [2] cb 48 [2] e5 6a [2] f1 71 [2] fe 6b [2] e0 76 [2] e2 77 [2] f9 71 [2] e5 76 [2] f9 59 }

  condition:
    any of them
}