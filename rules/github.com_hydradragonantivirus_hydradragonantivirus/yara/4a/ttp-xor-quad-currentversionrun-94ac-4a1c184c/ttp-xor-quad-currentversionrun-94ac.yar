rule TTP_XOR_QUAD_CurrentVersionRun_94ac {
  strings:
    $key_94ac = { c7 c3 [2] e3 cd [2] c8 e1 [2] e6 c3 [2] f2 d8 [2] fd c2 [2] e3 df [2] e1 de [2] fa d8 [2] e6 df [2] fa f0 }

  condition:
    any of them
}