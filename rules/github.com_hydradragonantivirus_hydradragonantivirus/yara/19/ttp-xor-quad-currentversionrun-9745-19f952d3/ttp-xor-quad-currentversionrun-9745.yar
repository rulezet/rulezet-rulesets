rule TTP_XOR_QUAD_CurrentVersionRun_9745 {
  strings:
    $key_9745 = { c4 2a [2] e0 24 [2] cb 08 [2] e5 2a [2] f1 31 [2] fe 2b [2] e0 36 [2] e2 37 [2] f9 31 [2] e5 36 [2] f9 19 }

  condition:
    any of them
}