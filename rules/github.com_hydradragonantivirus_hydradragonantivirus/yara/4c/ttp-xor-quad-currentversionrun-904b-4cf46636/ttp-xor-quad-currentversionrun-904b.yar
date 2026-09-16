rule TTP_XOR_QUAD_CurrentVersionRun_904b {
  strings:
    $key_904b = { c3 24 [2] e7 2a [2] cc 06 [2] e2 24 [2] f6 3f [2] f9 25 [2] e7 38 [2] e5 39 [2] fe 3f [2] e2 38 [2] fe 17 }

  condition:
    any of them
}