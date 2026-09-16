rule TTP_XOR_QUAD_CurrentVersionRun_9770 {
  strings:
    $key_9770 = { c4 1f [2] e0 11 [2] cb 3d [2] e5 1f [2] f1 04 [2] fe 1e [2] e0 03 [2] e2 02 [2] f9 04 [2] e5 03 [2] f9 2c }

  condition:
    any of them
}