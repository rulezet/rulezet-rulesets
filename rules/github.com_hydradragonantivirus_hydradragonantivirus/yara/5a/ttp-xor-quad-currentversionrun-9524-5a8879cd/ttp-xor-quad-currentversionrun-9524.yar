rule TTP_XOR_QUAD_CurrentVersionRun_9524 {
  strings:
    $key_9524 = { c6 4b [2] e2 45 [2] c9 69 [2] e7 4b [2] f3 50 [2] fc 4a [2] e2 57 [2] e0 56 [2] fb 50 [2] e7 57 [2] fb 78 }

  condition:
    any of them
}