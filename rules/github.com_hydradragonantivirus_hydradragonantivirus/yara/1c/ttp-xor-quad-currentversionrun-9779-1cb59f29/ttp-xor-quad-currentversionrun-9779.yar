rule TTP_XOR_QUAD_CurrentVersionRun_9779 {
  strings:
    $key_9779 = { c4 16 [2] e0 18 [2] cb 34 [2] e5 16 [2] f1 0d [2] fe 17 [2] e0 0a [2] e2 0b [2] f9 0d [2] e5 0a [2] f9 25 }

  condition:
    any of them
}