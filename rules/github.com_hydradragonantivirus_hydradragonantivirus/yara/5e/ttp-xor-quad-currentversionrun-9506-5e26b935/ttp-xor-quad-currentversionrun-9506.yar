rule TTP_XOR_QUAD_CurrentVersionRun_9506 {
  strings:
    $key_9506 = { c6 69 [2] e2 67 [2] c9 4b [2] e7 69 [2] f3 72 [2] fc 68 [2] e2 75 [2] e0 74 [2] fb 72 [2] e7 75 [2] fb 5a }

  condition:
    any of them
}