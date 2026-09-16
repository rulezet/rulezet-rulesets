rule TTP_XOR_QUAD_CurrentVersionRun_9565 {
  strings:
    $key_9565 = { c6 0a [2] e2 04 [2] c9 28 [2] e7 0a [2] f3 11 [2] fc 0b [2] e2 16 [2] e0 17 [2] fb 11 [2] e7 16 [2] fb 39 }

  condition:
    any of them
}