rule TTP_XOR_QUAD_CurrentVersionRun_9525 {
  strings:
    $key_9525 = { c6 4a [2] e2 44 [2] c9 68 [2] e7 4a [2] f3 51 [2] fc 4b [2] e2 56 [2] e0 57 [2] fb 51 [2] e7 56 [2] fb 79 }

  condition:
    any of them
}