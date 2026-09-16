rule TTP_XOR_QUAD_CurrentVersionRun_9519 {
  strings:
    $key_9519 = { c6 76 [2] e2 78 [2] c9 54 [2] e7 76 [2] f3 6d [2] fc 77 [2] e2 6a [2] e0 6b [2] fb 6d [2] e7 6a [2] fb 45 }

  condition:
    any of them
}