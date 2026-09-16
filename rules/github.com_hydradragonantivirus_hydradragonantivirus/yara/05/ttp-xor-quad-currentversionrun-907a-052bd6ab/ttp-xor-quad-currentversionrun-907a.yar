rule TTP_XOR_QUAD_CurrentVersionRun_907a {
  strings:
    $key_907a = { c3 15 [2] e7 1b [2] cc 37 [2] e2 15 [2] f6 0e [2] f9 14 [2] e7 09 [2] e5 08 [2] fe 0e [2] e2 09 [2] fe 26 }

  condition:
    any of them
}