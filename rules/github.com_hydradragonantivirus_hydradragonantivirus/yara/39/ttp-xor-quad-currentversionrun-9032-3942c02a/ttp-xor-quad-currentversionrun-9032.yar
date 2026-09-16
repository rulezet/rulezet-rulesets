rule TTP_XOR_QUAD_CurrentVersionRun_9032 {
  strings:
    $key_9032 = { c3 5d [2] e7 53 [2] cc 7f [2] e2 5d [2] f6 46 [2] f9 5c [2] e7 41 [2] e5 40 [2] fe 46 [2] e2 41 [2] fe 6e }

  condition:
    any of them
}