rule TTP_XOR_QUAD_CurrentVersionRun_9041 {
  strings:
    $key_9041 = { c3 2e [2] e7 20 [2] cc 0c [2] e2 2e [2] f6 35 [2] f9 2f [2] e7 32 [2] e5 33 [2] fe 35 [2] e2 32 [2] fe 1d }

  condition:
    any of them
}