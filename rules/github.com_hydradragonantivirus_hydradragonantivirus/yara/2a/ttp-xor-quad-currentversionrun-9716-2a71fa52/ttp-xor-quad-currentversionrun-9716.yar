rule TTP_XOR_QUAD_CurrentVersionRun_9716 {
  strings:
    $key_9716 = { c4 79 [2] e0 77 [2] cb 5b [2] e5 79 [2] f1 62 [2] fe 78 [2] e0 65 [2] e2 64 [2] f9 62 [2] e5 65 [2] f9 4a }

  condition:
    any of them
}