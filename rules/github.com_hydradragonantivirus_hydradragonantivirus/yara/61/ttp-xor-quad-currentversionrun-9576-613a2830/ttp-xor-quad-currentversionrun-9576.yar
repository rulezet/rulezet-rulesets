rule TTP_XOR_QUAD_CurrentVersionRun_9576 {
  strings:
    $key_9576 = { c6 19 [2] e2 17 [2] c9 3b [2] e7 19 [2] f3 02 [2] fc 18 [2] e2 05 [2] e0 04 [2] fb 02 [2] e7 05 [2] fb 2a }

  condition:
    any of them
}