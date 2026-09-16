rule TTP_XOR_QUAD_CurrentVersionRun_9537 {
  strings:
    $key_9537 = { c6 58 [2] e2 56 [2] c9 7a [2] e7 58 [2] f3 43 [2] fc 59 [2] e2 44 [2] e0 45 [2] fb 43 [2] e7 44 [2] fb 6b }

  condition:
    any of them
}