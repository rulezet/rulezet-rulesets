rule TTP_XOR_QUAD_CurrentVersionRun_9063 {
  strings:
    $key_9063 = { c3 0c [2] e7 02 [2] cc 2e [2] e2 0c [2] f6 17 [2] f9 0d [2] e7 10 [2] e5 11 [2] fe 17 [2] e2 10 [2] fe 3f }

  condition:
    any of them
}