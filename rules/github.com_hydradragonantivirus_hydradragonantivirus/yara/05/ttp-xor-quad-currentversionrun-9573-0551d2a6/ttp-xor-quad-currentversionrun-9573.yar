rule TTP_XOR_QUAD_CurrentVersionRun_9573 {
  strings:
    $key_9573 = { c6 1c [2] e2 12 [2] c9 3e [2] e7 1c [2] f3 07 [2] fc 1d [2] e2 00 [2] e0 01 [2] fb 07 [2] e7 00 [2] fb 2f }

  condition:
    any of them
}