rule TTP_XOR_QUAD_CurrentVersionRun_905f {
  strings:
    $key_905f = { c3 30 [2] e7 3e [2] cc 12 [2] e2 30 [2] f6 2b [2] f9 31 [2] e7 2c [2] e5 2d [2] fe 2b [2] e2 2c [2] fe 03 }

  condition:
    any of them
}