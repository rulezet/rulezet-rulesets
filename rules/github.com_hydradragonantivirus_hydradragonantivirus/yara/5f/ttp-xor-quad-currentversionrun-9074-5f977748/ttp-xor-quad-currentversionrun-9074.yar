rule TTP_XOR_QUAD_CurrentVersionRun_9074 {
  strings:
    $key_9074 = { c3 1b [2] e7 15 [2] cc 39 [2] e2 1b [2] f6 00 [2] f9 1a [2] e7 07 [2] e5 06 [2] fe 00 [2] e2 07 [2] fe 28 }

  condition:
    any of them
}