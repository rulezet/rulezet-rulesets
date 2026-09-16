rule TTP_XOR_QUAD_CurrentVersionRun_97b5 {
  strings:
    $key_97b5 = { c4 da [2] e0 d4 [2] cb f8 [2] e5 da [2] f1 c1 [2] fe db [2] e0 c6 [2] e2 c7 [2] f9 c1 [2] e5 c6 [2] f9 e9 }

  condition:
    any of them
}