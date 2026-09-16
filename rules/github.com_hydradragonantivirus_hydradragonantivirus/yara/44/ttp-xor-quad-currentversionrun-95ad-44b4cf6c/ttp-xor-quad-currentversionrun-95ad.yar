rule TTP_XOR_QUAD_CurrentVersionRun_95ad {
  strings:
    $key_95ad = { c6 c2 [2] e2 cc [2] c9 e0 [2] e7 c2 [2] f3 d9 [2] fc c3 [2] e2 de [2] e0 df [2] fb d9 [2] e7 de [2] fb f1 }

  condition:
    any of them
}