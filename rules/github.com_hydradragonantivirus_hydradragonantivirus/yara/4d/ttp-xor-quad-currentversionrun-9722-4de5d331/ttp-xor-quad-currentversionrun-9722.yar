rule TTP_XOR_QUAD_CurrentVersionRun_9722 {
  strings:
    $key_9722 = { c4 4d [2] e0 43 [2] cb 6f [2] e5 4d [2] f1 56 [2] fe 4c [2] e0 51 [2] e2 50 [2] f9 56 [2] e5 51 [2] f9 7e }

  condition:
    any of them
}