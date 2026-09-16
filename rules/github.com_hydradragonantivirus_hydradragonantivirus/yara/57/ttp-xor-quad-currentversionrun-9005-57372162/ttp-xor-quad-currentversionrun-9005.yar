rule TTP_XOR_QUAD_CurrentVersionRun_9005 {
  strings:
    $key_9005 = { c3 6a [2] e7 64 [2] cc 48 [2] e2 6a [2] f6 71 [2] f9 6b [2] e7 76 [2] e5 77 [2] fe 71 [2] e2 76 [2] fe 59 }

  condition:
    any of them
}