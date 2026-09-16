rule TTP_XOR_QUAD_CurrentVersionRun_9766 {
  strings:
    $key_9766 = { c4 09 [2] e0 07 [2] cb 2b [2] e5 09 [2] f1 12 [2] fe 08 [2] e0 15 [2] e2 14 [2] f9 12 [2] e5 15 [2] f9 3a }

  condition:
    any of them
}