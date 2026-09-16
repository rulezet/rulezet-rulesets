rule TTP_XOR_QUAD_CurrentVersionRun_906e {
  strings:
    $key_906e = { c3 01 [2] e7 0f [2] cc 23 [2] e2 01 [2] f6 1a [2] f9 00 [2] e7 1d [2] e5 1c [2] fe 1a [2] e2 1d [2] fe 32 }

  condition:
    any of them
}