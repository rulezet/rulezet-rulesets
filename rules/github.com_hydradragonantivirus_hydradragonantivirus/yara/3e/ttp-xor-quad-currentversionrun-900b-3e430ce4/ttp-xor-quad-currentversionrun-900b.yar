rule TTP_XOR_QUAD_CurrentVersionRun_900b {
  strings:
    $key_900b = { c3 64 [2] e7 6a [2] cc 46 [2] e2 64 [2] f6 7f [2] f9 65 [2] e7 78 [2] e5 79 [2] fe 7f [2] e2 78 [2] fe 57 }

  condition:
    any of them
}