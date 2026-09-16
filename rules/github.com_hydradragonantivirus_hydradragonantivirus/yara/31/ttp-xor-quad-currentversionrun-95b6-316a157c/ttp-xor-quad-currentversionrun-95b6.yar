rule TTP_XOR_QUAD_CurrentVersionRun_95b6 {
  strings:
    $key_95b6 = { c6 d9 [2] e2 d7 [2] c9 fb [2] e7 d9 [2] f3 c2 [2] fc d8 [2] e2 c5 [2] e0 c4 [2] fb c2 [2] e7 c5 [2] fb ea }

  condition:
    any of them
}