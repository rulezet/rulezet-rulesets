rule TTP_XOR_QUAD_CurrentVersionRun_9035 {
  strings:
    $key_9035 = { c3 5a [2] e7 54 [2] cc 78 [2] e2 5a [2] f6 41 [2] f9 5b [2] e7 46 [2] e5 47 [2] fe 41 [2] e2 46 [2] fe 69 }

  condition:
    any of them
}