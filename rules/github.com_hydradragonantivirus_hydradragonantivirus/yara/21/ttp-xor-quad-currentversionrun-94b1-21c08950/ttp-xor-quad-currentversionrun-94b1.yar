rule TTP_XOR_QUAD_CurrentVersionRun_94b1 {
  strings:
    $key_94b1 = { c7 de [2] e3 d0 [2] c8 fc [2] e6 de [2] f2 c5 [2] fd df [2] e3 c2 [2] e1 c3 [2] fa c5 [2] e6 c2 [2] fa ed }

  condition:
    any of them
}