rule TTP_XOR_QUAD_CurrentVersionRun_8aad {
  strings:
    $key_8aad = { d9 c2 [2] fd cc [2] d6 e0 [2] f8 c2 [2] ec d9 [2] e3 c3 [2] fd de [2] ff df [2] e4 d9 [2] f8 de [2] e4 f1 }

  condition:
    any of them
}