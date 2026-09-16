rule TTP_XOR_QUAD_CurrentVersionRun_95d1 {
  strings:
    $key_95d1 = { c6 be [2] e2 b0 [2] c9 9c [2] e7 be [2] f3 a5 [2] fc bf [2] e2 a2 [2] e0 a3 [2] fb a5 [2] e7 a2 [2] fb 8d }

  condition:
    any of them
}