rule TTP_XOR_QUAD_CurrentVersionRun_9741 {
  strings:
    $key_9741 = { c4 2e [2] e0 20 [2] cb 0c [2] e5 2e [2] f1 35 [2] fe 2f [2] e0 32 [2] e2 33 [2] f9 35 [2] e5 32 [2] f9 1d }

  condition:
    any of them
}