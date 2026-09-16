rule TTP_XOR_QUAD_CurrentVersionRun_9557 {
  strings:
    $key_9557 = { c6 38 [2] e2 36 [2] c9 1a [2] e7 38 [2] f3 23 [2] fc 39 [2] e2 24 [2] e0 25 [2] fb 23 [2] e7 24 [2] fb 0b }

  condition:
    any of them
}