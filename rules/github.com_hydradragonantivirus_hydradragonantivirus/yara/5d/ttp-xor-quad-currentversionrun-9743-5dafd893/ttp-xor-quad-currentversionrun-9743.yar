rule TTP_XOR_QUAD_CurrentVersionRun_9743 {
  strings:
    $key_9743 = { c4 2c [2] e0 22 [2] cb 0e [2] e5 2c [2] f1 37 [2] fe 2d [2] e0 30 [2] e2 31 [2] f9 37 [2] e5 30 [2] f9 1f }

  condition:
    any of them
}