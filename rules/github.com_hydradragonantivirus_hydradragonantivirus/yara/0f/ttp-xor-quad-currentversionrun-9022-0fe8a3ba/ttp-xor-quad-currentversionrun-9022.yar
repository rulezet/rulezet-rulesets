rule TTP_XOR_QUAD_CurrentVersionRun_9022 {
  strings:
    $key_9022 = { c3 4d [2] e7 43 [2] cc 6f [2] e2 4d [2] f6 56 [2] f9 4c [2] e7 51 [2] e5 50 [2] fe 56 [2] e2 51 [2] fe 7e }

  condition:
    any of them
}