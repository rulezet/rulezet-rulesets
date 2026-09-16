rule TTP_XOR_QUAD_CurrentVersionRun_9055 {
  strings:
    $key_9055 = { c3 3a [2] e7 34 [2] cc 18 [2] e2 3a [2] f6 21 [2] f9 3b [2] e7 26 [2] e5 27 [2] fe 21 [2] e2 26 [2] fe 09 }

  condition:
    any of them
}