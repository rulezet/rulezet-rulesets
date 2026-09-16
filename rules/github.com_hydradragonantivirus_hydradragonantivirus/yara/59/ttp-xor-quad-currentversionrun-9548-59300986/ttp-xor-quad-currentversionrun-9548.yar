rule TTP_XOR_QUAD_CurrentVersionRun_9548 {
  strings:
    $key_9548 = { c6 27 [2] e2 29 [2] c9 05 [2] e7 27 [2] f3 3c [2] fc 26 [2] e2 3b [2] e0 3a [2] fb 3c [2] e7 3b [2] fb 14 }

  condition:
    any of them
}