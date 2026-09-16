rule TTP_XOR_QUAD_CurrentVersionRun_93a4 {
  strings:
    $key_93a4 = { c0 cb [2] e4 c5 [2] cf e9 [2] e1 cb [2] f5 d0 [2] fa ca [2] e4 d7 [2] e6 d6 [2] fd d0 [2] e1 d7 [2] fd f8 }

  condition:
    any of them
}