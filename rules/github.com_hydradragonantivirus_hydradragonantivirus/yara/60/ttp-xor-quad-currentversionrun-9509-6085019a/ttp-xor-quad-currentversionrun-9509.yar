rule TTP_XOR_QUAD_CurrentVersionRun_9509 {
  strings:
    $key_9509 = { c6 66 [2] e2 68 [2] c9 44 [2] e7 66 [2] f3 7d [2] fc 67 [2] e2 7a [2] e0 7b [2] fb 7d [2] e7 7a [2] fb 55 }

  condition:
    any of them
}