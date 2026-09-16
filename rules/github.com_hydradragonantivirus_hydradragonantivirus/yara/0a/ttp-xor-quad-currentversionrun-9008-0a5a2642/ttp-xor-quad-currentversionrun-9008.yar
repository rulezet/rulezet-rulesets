rule TTP_XOR_QUAD_CurrentVersionRun_9008 {
  strings:
    $key_9008 = { c3 67 [2] e7 69 [2] cc 45 [2] e2 67 [2] f6 7c [2] f9 66 [2] e7 7b [2] e5 7a [2] fe 7c [2] e2 7b [2] fe 54 }

  condition:
    any of them
}