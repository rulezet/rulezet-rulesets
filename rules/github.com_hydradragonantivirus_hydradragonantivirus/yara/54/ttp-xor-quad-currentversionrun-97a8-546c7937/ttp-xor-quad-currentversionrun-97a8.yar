rule TTP_XOR_QUAD_CurrentVersionRun_97a8 {
  strings:
    $key_97a8 = { c4 c7 [2] e0 c9 [2] cb e5 [2] e5 c7 [2] f1 dc [2] fe c6 [2] e0 db [2] e2 da [2] f9 dc [2] e5 db [2] f9 f4 }

  condition:
    any of them
}