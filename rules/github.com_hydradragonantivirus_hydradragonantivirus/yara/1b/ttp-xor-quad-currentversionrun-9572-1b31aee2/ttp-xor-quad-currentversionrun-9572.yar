rule TTP_XOR_QUAD_CurrentVersionRun_9572 {
  strings:
    $key_9572 = { c6 1d [2] e2 13 [2] c9 3f [2] e7 1d [2] f3 06 [2] fc 1c [2] e2 01 [2] e0 00 [2] fb 06 [2] e7 01 [2] fb 2e }

  condition:
    any of them
}