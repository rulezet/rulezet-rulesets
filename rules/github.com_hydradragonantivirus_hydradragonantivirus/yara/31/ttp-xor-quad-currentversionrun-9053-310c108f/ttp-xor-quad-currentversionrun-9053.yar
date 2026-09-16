rule TTP_XOR_QUAD_CurrentVersionRun_9053 {
  strings:
    $key_9053 = { c3 3c [2] e7 32 [2] cc 1e [2] e2 3c [2] f6 27 [2] f9 3d [2] e7 20 [2] e5 21 [2] fe 27 [2] e2 20 [2] fe 0f }

  condition:
    any of them
}