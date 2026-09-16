rule TTP_XOR_QUAD_CurrentVersionRun_9564 {
  strings:
    $key_9564 = { c6 0b [2] e2 05 [2] c9 29 [2] e7 0b [2] f3 10 [2] fc 0a [2] e2 17 [2] e0 16 [2] fb 10 [2] e7 17 [2] fb 38 }

  condition:
    any of them
}