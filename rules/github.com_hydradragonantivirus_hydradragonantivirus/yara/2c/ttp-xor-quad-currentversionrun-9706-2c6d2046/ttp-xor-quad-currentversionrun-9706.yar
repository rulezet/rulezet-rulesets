rule TTP_XOR_QUAD_CurrentVersionRun_9706 {
  strings:
    $key_9706 = { c4 69 [2] e0 67 [2] cb 4b [2] e5 69 [2] f1 72 [2] fe 68 [2] e0 75 [2] e2 74 [2] f9 72 [2] e5 75 [2] f9 5a }

  condition:
    any of them
}