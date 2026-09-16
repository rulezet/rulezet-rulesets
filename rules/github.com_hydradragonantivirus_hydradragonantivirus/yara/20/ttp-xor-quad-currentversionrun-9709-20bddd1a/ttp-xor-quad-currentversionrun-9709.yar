rule TTP_XOR_QUAD_CurrentVersionRun_9709 {
  strings:
    $key_9709 = { c4 66 [2] e0 68 [2] cb 44 [2] e5 66 [2] f1 7d [2] fe 67 [2] e0 7a [2] e2 7b [2] f9 7d [2] e5 7a [2] f9 55 }

  condition:
    any of them
}