rule TTP_XOR_QUAD_CurrentVersionRun_95a8 {
  strings:
    $key_95a8 = { c6 c7 [2] e2 c9 [2] c9 e5 [2] e7 c7 [2] f3 dc [2] fc c6 [2] e2 db [2] e0 da [2] fb dc [2] e7 db [2] fb f4 }

  condition:
    any of them
}