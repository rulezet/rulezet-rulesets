rule TTP_XOR_QUAD_CurrentVersionRun_97ad {
  strings:
    $key_97ad = { c4 c2 [2] e0 cc [2] cb e0 [2] e5 c2 [2] f1 d9 [2] fe c3 [2] e0 de [2] e2 df [2] f9 d9 [2] e5 de [2] f9 f1 }

  condition:
    any of them
}