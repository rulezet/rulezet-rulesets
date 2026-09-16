rule TTP_XOR_QUAD_CurrentVersionRun_9518 {
  strings:
    $key_9518 = { c6 77 [2] e2 79 [2] c9 55 [2] e7 77 [2] f3 6c [2] fc 76 [2] e2 6b [2] e0 6a [2] fb 6c [2] e7 6b [2] fb 44 }

  condition:
    any of them
}