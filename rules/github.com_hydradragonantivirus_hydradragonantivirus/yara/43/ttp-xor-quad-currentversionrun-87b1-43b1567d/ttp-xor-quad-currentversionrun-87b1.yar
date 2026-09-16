rule TTP_XOR_QUAD_CurrentVersionRun_87b1 {
  strings:
    $key_87b1 = { d4 de [2] f0 d0 [2] db fc [2] f5 de [2] e1 c5 [2] ee df [2] f0 c2 [2] f2 c3 [2] e9 c5 [2] f5 c2 [2] e9 ed }

  condition:
    any of them
}