rule TTP_XOR_QUAD_CurrentVersionRun_9761 {
  strings:
    $key_9761 = { c4 0e [2] e0 00 [2] cb 2c [2] e5 0e [2] f1 15 [2] fe 0f [2] e0 12 [2] e2 13 [2] f9 15 [2] e5 12 [2] f9 3d }

  condition:
    any of them
}