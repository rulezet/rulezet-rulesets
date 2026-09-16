rule TTP_XOR_QUAD_CurrentVersionRun_93ad {
  strings:
    $key_93ad = { c0 c2 [2] e4 cc [2] cf e0 [2] e1 c2 [2] f5 d9 [2] fa c3 [2] e4 de [2] e6 df [2] fd d9 [2] e1 de [2] fd f1 }

  condition:
    any of them
}