rule TTP_XOR_QUAD_CurrentVersionRun_9562 {
  strings:
    $key_9562 = { c6 0d [2] e2 03 [2] c9 2f [2] e7 0d [2] f3 16 [2] fc 0c [2] e2 11 [2] e0 10 [2] fb 16 [2] e7 11 [2] fb 3e }

  condition:
    any of them
}