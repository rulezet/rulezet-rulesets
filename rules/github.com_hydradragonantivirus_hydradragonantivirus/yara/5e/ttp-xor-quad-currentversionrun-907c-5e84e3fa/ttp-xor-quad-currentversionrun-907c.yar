rule TTP_XOR_QUAD_CurrentVersionRun_907c {
  strings:
    $key_907c = { c3 13 [2] e7 1d [2] cc 31 [2] e2 13 [2] f6 08 [2] f9 12 [2] e7 0f [2] e5 0e [2] fe 08 [2] e2 0f [2] fe 20 }

  condition:
    any of them
}