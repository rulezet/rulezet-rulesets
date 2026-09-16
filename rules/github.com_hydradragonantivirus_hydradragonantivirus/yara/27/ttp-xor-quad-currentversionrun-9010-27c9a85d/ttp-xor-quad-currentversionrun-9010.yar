rule TTP_XOR_QUAD_CurrentVersionRun_9010 {
  strings:
    $key_9010 = { c3 7f [2] e7 71 [2] cc 5d [2] e2 7f [2] f6 64 [2] f9 7e [2] e7 63 [2] e5 62 [2] fe 64 [2] e2 63 [2] fe 4c }

  condition:
    any of them
}