rule TTP_XOR_QUAD_CurrentVersionRun_9048 {
  strings:
    $key_9048 = { c3 27 [2] e7 29 [2] cc 05 [2] e2 27 [2] f6 3c [2] f9 26 [2] e7 3b [2] e5 3a [2] fe 3c [2] e2 3b [2] fe 14 }

  condition:
    any of them
}