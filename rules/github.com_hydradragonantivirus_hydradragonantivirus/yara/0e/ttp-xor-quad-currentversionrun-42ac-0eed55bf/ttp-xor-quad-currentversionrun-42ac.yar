rule TTP_XOR_QUAD_CurrentVersionRun_42ac {
  strings:
    $key_42ac = { 11 c3 [2] 35 cd [2] 1e e1 [2] 30 c3 [2] 24 d8 [2] 2b c2 [2] 35 df [2] 37 de [2] 2c d8 [2] 30 df [2] 2c f0 }

  condition:
    any of them
}