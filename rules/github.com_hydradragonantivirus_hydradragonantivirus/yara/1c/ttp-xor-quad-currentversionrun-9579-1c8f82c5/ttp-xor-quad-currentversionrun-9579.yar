rule TTP_XOR_QUAD_CurrentVersionRun_9579 {
  strings:
    $key_9579 = { c6 16 [2] e2 18 [2] c9 34 [2] e7 16 [2] f3 0d [2] fc 17 [2] e2 0a [2] e0 0b [2] fb 0d [2] e7 0a [2] fb 25 }

  condition:
    any of them
}