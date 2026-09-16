rule TTP_XOR_QUAD_CurrentVersionRun_9732 {
  strings:
    $key_9732 = { c4 5d [2] e0 53 [2] cb 7f [2] e5 5d [2] f1 46 [2] fe 5c [2] e0 41 [2] e2 40 [2] f9 46 [2] e5 41 [2] f9 6e }

  condition:
    any of them
}