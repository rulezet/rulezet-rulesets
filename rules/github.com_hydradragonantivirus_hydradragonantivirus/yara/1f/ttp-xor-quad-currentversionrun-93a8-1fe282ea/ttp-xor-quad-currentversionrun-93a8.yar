rule TTP_XOR_QUAD_CurrentVersionRun_93a8 {
  strings:
    $key_93a8 = { c0 c7 [2] e4 c9 [2] cf e5 [2] e1 c7 [2] f5 dc [2] fa c6 [2] e4 db [2] e6 da [2] fd dc [2] e1 db [2] fd f4 }

  condition:
    any of them
}