rule TTP_XOR_QUAD_CurrentVersionRun_9060 {
  strings:
    $key_9060 = { c3 0f [2] e7 01 [2] cc 2d [2] e2 0f [2] f6 14 [2] f9 0e [2] e7 13 [2] e5 12 [2] fe 14 [2] e2 13 [2] fe 3c }

  condition:
    any of them
}