rule TTP_XOR_QUAD_CurrentVersionRun_51ac {
  strings:
    $key_51ac = { 02 c3 [2] 26 cd [2] 0d e1 [2] 23 c3 [2] 37 d8 [2] 38 c2 [2] 26 df [2] 24 de [2] 3f d8 [2] 23 df [2] 3f f0 }

  condition:
    any of them
}