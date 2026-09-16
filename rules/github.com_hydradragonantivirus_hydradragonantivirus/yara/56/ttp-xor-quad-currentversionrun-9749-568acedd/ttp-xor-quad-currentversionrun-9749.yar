rule TTP_XOR_QUAD_CurrentVersionRun_9749 {
  strings:
    $key_9749 = { c4 26 [2] e0 28 [2] cb 04 [2] e5 26 [2] f1 3d [2] fe 27 [2] e0 3a [2] e2 3b [2] f9 3d [2] e5 3a [2] f9 15 }

  condition:
    any of them
}