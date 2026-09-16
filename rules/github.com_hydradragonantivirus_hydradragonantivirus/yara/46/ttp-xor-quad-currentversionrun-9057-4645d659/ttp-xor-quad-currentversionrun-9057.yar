rule TTP_XOR_QUAD_CurrentVersionRun_9057 {
  strings:
    $key_9057 = { c3 38 [2] e7 36 [2] cc 1a [2] e2 38 [2] f6 23 [2] f9 39 [2] e7 24 [2] e5 25 [2] fe 23 [2] e2 24 [2] fe 0b }

  condition:
    any of them
}