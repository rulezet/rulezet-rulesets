rule TTP_XOR_QUAD_CurrentVersionRun_94ad {
  strings:
    $key_94ad = { c7 c2 [2] e3 cc [2] c8 e0 [2] e6 c2 [2] f2 d9 [2] fd c3 [2] e3 de [2] e1 df [2] fa d9 [2] e6 de [2] fa f1 }

  condition:
    any of them
}