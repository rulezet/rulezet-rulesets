rule TTP_XOR_QUAD_CurrentVersionRun_9043 {
  strings:
    $key_9043 = { c3 2c [2] e7 22 [2] cc 0e [2] e2 2c [2] f6 37 [2] f9 2d [2] e7 30 [2] e5 31 [2] fe 37 [2] e2 30 [2] fe 1f }

  condition:
    any of them
}