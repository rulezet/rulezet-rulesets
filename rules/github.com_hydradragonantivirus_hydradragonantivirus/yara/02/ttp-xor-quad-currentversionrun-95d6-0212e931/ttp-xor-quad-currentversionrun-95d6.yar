rule TTP_XOR_QUAD_CurrentVersionRun_95d6 {
  strings:
    $key_95d6 = { c6 b9 [2] e2 b7 [2] c9 9b [2] e7 b9 [2] f3 a2 [2] fc b8 [2] e2 a5 [2] e0 a4 [2] fb a2 [2] e7 a5 [2] fb 8a }

  condition:
    any of them
}