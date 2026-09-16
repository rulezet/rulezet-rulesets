rule TTP_XOR_QUAD_CurrentVersionRun_9769 {
  strings:
    $key_9769 = { c4 06 [2] e0 08 [2] cb 24 [2] e5 06 [2] f1 1d [2] fe 07 [2] e0 1a [2] e2 1b [2] f9 1d [2] e5 1a [2] f9 35 }

  condition:
    any of them
}