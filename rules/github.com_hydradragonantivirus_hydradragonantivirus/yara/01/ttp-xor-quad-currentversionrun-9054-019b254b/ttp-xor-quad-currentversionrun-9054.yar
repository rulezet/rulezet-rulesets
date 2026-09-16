rule TTP_XOR_QUAD_CurrentVersionRun_9054 {
  strings:
    $key_9054 = { c3 3b [2] e7 35 [2] cc 19 [2] e2 3b [2] f6 20 [2] f9 3a [2] e7 27 [2] e5 26 [2] fe 20 [2] e2 27 [2] fe 08 }

  condition:
    any of them
}