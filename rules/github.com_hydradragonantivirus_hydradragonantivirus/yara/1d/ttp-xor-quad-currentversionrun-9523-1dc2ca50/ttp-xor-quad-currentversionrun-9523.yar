rule TTP_XOR_QUAD_CurrentVersionRun_9523 {
  strings:
    $key_9523 = { c6 4c [2] e2 42 [2] c9 6e [2] e7 4c [2] f3 57 [2] fc 4d [2] e2 50 [2] e0 51 [2] fb 57 [2] e7 50 [2] fb 7f }

  condition:
    any of them
}