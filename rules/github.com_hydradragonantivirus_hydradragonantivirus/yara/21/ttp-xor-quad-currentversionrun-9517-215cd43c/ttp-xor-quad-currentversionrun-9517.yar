rule TTP_XOR_QUAD_CurrentVersionRun_9517 {
  strings:
    $key_9517 = { c6 78 [2] e2 76 [2] c9 5a [2] e7 78 [2] f3 63 [2] fc 79 [2] e2 64 [2] e0 65 [2] fb 63 [2] e7 64 [2] fb 4b }

  condition:
    any of them
}