rule TTP_XOR_QUAD_CurrentVersionRun_9068 {
  strings:
    $key_9068 = { c3 07 [2] e7 09 [2] cc 25 [2] e2 07 [2] f6 1c [2] f9 06 [2] e7 1b [2] e5 1a [2] fe 1c [2] e2 1b [2] fe 34 }

  condition:
    any of them
}