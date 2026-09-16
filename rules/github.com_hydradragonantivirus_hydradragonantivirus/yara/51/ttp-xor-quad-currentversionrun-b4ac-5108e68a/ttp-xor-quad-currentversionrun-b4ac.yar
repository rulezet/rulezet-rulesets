rule TTP_XOR_QUAD_CurrentVersionRun_b4ac {
  strings:
    $key_b4ac = { e7 c3 [2] c3 cd [2] e8 e1 [2] c6 c3 [2] d2 d8 [2] dd c2 [2] c3 df [2] c1 de [2] da d8 [2] c6 df [2] da f0 }

  condition:
    any of them
}