rule TTP_XOR_QUAD_CurrentVersionRun_9038 {
  strings:
    $key_9038 = { c3 57 [2] e7 59 [2] cc 75 [2] e2 57 [2] f6 4c [2] f9 56 [2] e7 4b [2] e5 4a [2] fe 4c [2] e2 4b [2] fe 64 }

  condition:
    any of them
}