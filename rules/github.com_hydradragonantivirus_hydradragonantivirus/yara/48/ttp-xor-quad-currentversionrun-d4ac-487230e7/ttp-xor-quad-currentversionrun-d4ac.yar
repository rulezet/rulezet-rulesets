rule TTP_XOR_QUAD_CurrentVersionRun_d4ac {
  strings:
    $key_d4ac = { 87 c3 [2] a3 cd [2] 88 e1 [2] a6 c3 [2] b2 d8 [2] bd c2 [2] a3 df [2] a1 de [2] ba d8 [2] a6 df [2] ba f0 }

  condition:
    any of them
}