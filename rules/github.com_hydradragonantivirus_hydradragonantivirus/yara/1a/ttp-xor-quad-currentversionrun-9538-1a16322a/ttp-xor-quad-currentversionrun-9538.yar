rule TTP_XOR_QUAD_CurrentVersionRun_9538 {
  strings:
    $key_9538 = { c6 57 [2] e2 59 [2] c9 75 [2] e7 57 [2] f3 4c [2] fc 56 [2] e2 4b [2] e0 4a [2] fb 4c [2] e7 4b [2] fb 64 }

  condition:
    any of them
}