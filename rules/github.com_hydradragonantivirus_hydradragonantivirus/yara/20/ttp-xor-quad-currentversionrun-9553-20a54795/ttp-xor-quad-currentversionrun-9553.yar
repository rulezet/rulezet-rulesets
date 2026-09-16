rule TTP_XOR_QUAD_CurrentVersionRun_9553 {
  strings:
    $key_9553 = { c6 3c [2] e2 32 [2] c9 1e [2] e7 3c [2] f3 27 [2] fc 3d [2] e2 20 [2] e0 21 [2] fb 27 [2] e7 20 [2] fb 0f }

  condition:
    any of them
}