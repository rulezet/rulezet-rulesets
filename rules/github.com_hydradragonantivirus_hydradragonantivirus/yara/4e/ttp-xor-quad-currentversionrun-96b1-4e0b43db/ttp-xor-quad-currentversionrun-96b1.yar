rule TTP_XOR_QUAD_CurrentVersionRun_96b1 {
  strings:
    $key_96b1 = { c5 de [2] e1 d0 [2] ca fc [2] e4 de [2] f0 c5 [2] ff df [2] e1 c2 [2] e3 c3 [2] f8 c5 [2] e4 c2 [2] f8 ed }

  condition:
    any of them
}