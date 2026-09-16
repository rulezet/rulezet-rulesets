rule TTP_XOR_QUAD_CurrentVersionRun_9556 {
  strings:
    $key_9556 = { c6 39 [2] e2 37 [2] c9 1b [2] e7 39 [2] f3 22 [2] fc 38 [2] e2 25 [2] e0 24 [2] fb 22 [2] e7 25 [2] fb 0a }

  condition:
    any of them
}