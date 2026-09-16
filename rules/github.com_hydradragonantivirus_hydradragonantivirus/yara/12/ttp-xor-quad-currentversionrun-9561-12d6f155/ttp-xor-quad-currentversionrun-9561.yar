rule TTP_XOR_QUAD_CurrentVersionRun_9561 {
  strings:
    $key_9561 = { c6 0e [2] e2 00 [2] c9 2c [2] e7 0e [2] f3 15 [2] fc 0f [2] e2 12 [2] e0 13 [2] fb 15 [2] e7 12 [2] fb 3d }

  condition:
    any of them
}