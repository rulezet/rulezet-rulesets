rule TTP_XOR_QUAD_CurrentVersionRun_95f5 {
  strings:
    $key_95f5 = { c6 9a [2] e2 94 [2] c9 b8 [2] e7 9a [2] f3 81 [2] fc 9b [2] e2 86 [2] e0 87 [2] fb 81 [2] e7 86 [2] fb a9 }

  condition:
    any of them
}