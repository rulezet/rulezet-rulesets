rule TTP_XOR_QUAD_CurrentVersionRun_95d2 {
  strings:
    $key_95d2 = { c6 bd [2] e2 b3 [2] c9 9f [2] e7 bd [2] f3 a6 [2] fc bc [2] e2 a1 [2] e0 a0 [2] fb a6 [2] e7 a1 [2] fb 8e }

  condition:
    any of them
}