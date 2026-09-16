rule TTP_XOR_QUAD_CurrentVersionRun_9009 {
  strings:
    $key_9009 = { c3 66 [2] e7 68 [2] cc 44 [2] e2 66 [2] f6 7d [2] f9 67 [2] e7 7a [2] e5 7b [2] fe 7d [2] e2 7a [2] fe 55 }

  condition:
    any of them
}