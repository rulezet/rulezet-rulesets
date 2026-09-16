rule TTP_XOR_QUAD_CurrentVersionRun_9753 {
  strings:
    $key_9753 = { c4 3c [2] e0 32 [2] cb 1e [2] e5 3c [2] f1 27 [2] fe 3d [2] e0 20 [2] e2 21 [2] f9 27 [2] e5 20 [2] f9 0f }

  condition:
    any of them
}