rule TTP_XOR_QUAD_CurrentVersionRun_93ac {
  strings:
    $key_93ac = { c0 c3 [2] e4 cd [2] cf e1 [2] e1 c3 [2] f5 d8 [2] fa c2 [2] e4 df [2] e6 de [2] fd d8 [2] e1 df [2] fd f0 }

  condition:
    any of them
}