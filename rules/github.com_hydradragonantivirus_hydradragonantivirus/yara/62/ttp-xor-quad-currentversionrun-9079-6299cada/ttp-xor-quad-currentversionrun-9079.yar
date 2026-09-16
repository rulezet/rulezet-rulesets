rule TTP_XOR_QUAD_CurrentVersionRun_9079 {
  strings:
    $key_9079 = { c3 16 [2] e7 18 [2] cc 34 [2] e2 16 [2] f6 0d [2] f9 17 [2] e7 0a [2] e5 0b [2] fe 0d [2] e2 0a [2] fe 25 }

  condition:
    any of them
}