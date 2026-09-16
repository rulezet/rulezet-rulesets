rule TTP_XOR_QUAD_CurrentVersionRun_95f4 {
  strings:
    $key_95f4 = { c6 9b [2] e2 95 [2] c9 b9 [2] e7 9b [2] f3 80 [2] fc 9a [2] e2 87 [2] e0 86 [2] fb 80 [2] e7 87 [2] fb a8 }

  condition:
    any of them
}