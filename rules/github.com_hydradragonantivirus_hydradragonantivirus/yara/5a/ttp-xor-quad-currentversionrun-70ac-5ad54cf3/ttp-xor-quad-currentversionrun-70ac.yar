rule TTP_XOR_QUAD_CurrentVersionRun_70ac {
  strings:
    $key_70ac = { 23 c3 [2] 07 cd [2] 2c e1 [2] 02 c3 [2] 16 d8 [2] 19 c2 [2] 07 df [2] 05 de [2] 1e d8 [2] 02 df [2] 1e f0 }

  condition:
    any of them
}