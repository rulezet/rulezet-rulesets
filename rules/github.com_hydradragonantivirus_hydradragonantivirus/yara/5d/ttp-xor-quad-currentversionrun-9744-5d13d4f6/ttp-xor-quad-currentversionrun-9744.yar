rule TTP_XOR_QUAD_CurrentVersionRun_9744 {
  strings:
    $key_9744 = { c4 2b [2] e0 25 [2] cb 09 [2] e5 2b [2] f1 30 [2] fe 2a [2] e0 37 [2] e2 36 [2] f9 30 [2] e5 37 [2] f9 18 }

  condition:
    any of them
}