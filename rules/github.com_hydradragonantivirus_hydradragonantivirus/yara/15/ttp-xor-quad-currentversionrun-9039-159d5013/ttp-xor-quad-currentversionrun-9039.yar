rule TTP_XOR_QUAD_CurrentVersionRun_9039 {
  strings:
    $key_9039 = { c3 56 [2] e7 58 [2] cc 74 [2] e2 56 [2] f6 4d [2] f9 57 [2] e7 4a [2] e5 4b [2] fe 4d [2] e2 4a [2] fe 65 }

  condition:
    any of them
}