rule TTP_XOR_QUAD_CurrentVersionRun_e2ac {
  strings:
    $key_e2ac = { b1 c3 [2] 95 cd [2] be e1 [2] 90 c3 [2] 84 d8 [2] 8b c2 [2] 95 df [2] 97 de [2] 8c d8 [2] 90 df [2] 8c f0 }

  condition:
    any of them
}