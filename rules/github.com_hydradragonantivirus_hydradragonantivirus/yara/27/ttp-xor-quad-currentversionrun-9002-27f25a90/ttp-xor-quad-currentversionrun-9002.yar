rule TTP_XOR_QUAD_CurrentVersionRun_9002 {
  strings:
    $key_9002 = { c3 6d [2] e7 63 [2] cc 4f [2] e2 6d [2] f6 76 [2] f9 6c [2] e7 71 [2] e5 70 [2] fe 76 [2] e2 71 [2] fe 5e }

  condition:
    any of them
}