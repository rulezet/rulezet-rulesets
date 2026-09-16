rule TTP_XOR_QUAD_CurrentVersionRun_9042 {
  strings:
    $key_9042 = { c3 2d [2] e7 23 [2] cc 0f [2] e2 2d [2] f6 36 [2] f9 2c [2] e7 31 [2] e5 30 [2] fe 36 [2] e2 31 [2] fe 1e }

  condition:
    any of them
}