rule TTP_XOR_QUAD_CurrentVersionRun_9515 {
  strings:
    $key_9515 = { c6 7a [2] e2 74 [2] c9 58 [2] e7 7a [2] f3 61 [2] fc 7b [2] e2 66 [2] e0 67 [2] fb 61 [2] e7 66 [2] fb 49 }

  condition:
    any of them
}