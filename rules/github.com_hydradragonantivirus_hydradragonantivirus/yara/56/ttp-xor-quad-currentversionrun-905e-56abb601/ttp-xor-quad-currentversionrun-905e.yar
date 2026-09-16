rule TTP_XOR_QUAD_CurrentVersionRun_905e {
  strings:
    $key_905e = { c3 31 [2] e7 3f [2] cc 13 [2] e2 31 [2] f6 2a [2] f9 30 [2] e7 2d [2] e5 2c [2] fe 2a [2] e2 2d [2] fe 02 }

  condition:
    any of them
}