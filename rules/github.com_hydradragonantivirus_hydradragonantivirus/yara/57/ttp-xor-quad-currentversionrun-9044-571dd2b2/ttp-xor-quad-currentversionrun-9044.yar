rule TTP_XOR_QUAD_CurrentVersionRun_9044 {
  strings:
    $key_9044 = { c3 2b [2] e7 25 [2] cc 09 [2] e2 2b [2] f6 30 [2] f9 2a [2] e7 37 [2] e5 36 [2] fe 30 [2] e2 37 [2] fe 18 }

  condition:
    any of them
}