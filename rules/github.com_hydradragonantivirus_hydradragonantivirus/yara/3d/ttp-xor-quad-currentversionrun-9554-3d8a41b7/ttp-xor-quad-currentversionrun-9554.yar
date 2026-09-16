rule TTP_XOR_QUAD_CurrentVersionRun_9554 {
  strings:
    $key_9554 = { c6 3b [2] e2 35 [2] c9 19 [2] e7 3b [2] f3 20 [2] fc 3a [2] e2 27 [2] e0 26 [2] fb 20 [2] e7 27 [2] fb 08 }

  condition:
    any of them
}