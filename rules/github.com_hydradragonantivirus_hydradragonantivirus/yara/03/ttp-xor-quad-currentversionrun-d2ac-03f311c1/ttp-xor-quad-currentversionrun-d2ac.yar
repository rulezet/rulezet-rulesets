rule TTP_XOR_QUAD_CurrentVersionRun_d2ac {
  strings:
    $key_d2ac = { 81 c3 [2] a5 cd [2] 8e e1 [2] a0 c3 [2] b4 d8 [2] bb c2 [2] a5 df [2] a7 de [2] bc d8 [2] a0 df [2] bc f0 }

  condition:
    any of them
}