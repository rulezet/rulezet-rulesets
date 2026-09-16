rule TTP_XOR_QUAD_CurrentVersionRun_9759 {
  strings:
    $key_9759 = { c4 36 [2] e0 38 [2] cb 14 [2] e5 36 [2] f1 2d [2] fe 37 [2] e0 2a [2] e2 2b [2] f9 2d [2] e5 2a [2] f9 05 }

  condition:
    any of them
}