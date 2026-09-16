rule TTP_XOR_QUAD_CurrentVersionRun_9011 {
  strings:
    $key_9011 = { c3 7e [2] e7 70 [2] cc 5c [2] e2 7e [2] f6 65 [2] f9 7f [2] e7 62 [2] e5 63 [2] fe 65 [2] e2 62 [2] fe 4d }

  condition:
    any of them
}