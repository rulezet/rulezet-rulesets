rule TTP_XOR_QUAD_CurrentVersionRun_9713 {
  strings:
    $key_9713 = { c4 7c [2] e0 72 [2] cb 5e [2] e5 7c [2] f1 67 [2] fe 7d [2] e0 60 [2] e2 61 [2] f9 67 [2] e5 60 [2] f9 4f }

  condition:
    any of them
}