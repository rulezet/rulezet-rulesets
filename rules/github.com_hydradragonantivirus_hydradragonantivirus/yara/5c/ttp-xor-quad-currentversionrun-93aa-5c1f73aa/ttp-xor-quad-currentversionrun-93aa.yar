rule TTP_XOR_QUAD_CurrentVersionRun_93aa {
  strings:
    $key_93aa = { c0 c5 [2] e4 cb [2] cf e7 [2] e1 c5 [2] f5 de [2] fa c4 [2] e4 d9 [2] e6 d8 [2] fd de [2] e1 d9 [2] fd f6 }

  condition:
    any of them
}