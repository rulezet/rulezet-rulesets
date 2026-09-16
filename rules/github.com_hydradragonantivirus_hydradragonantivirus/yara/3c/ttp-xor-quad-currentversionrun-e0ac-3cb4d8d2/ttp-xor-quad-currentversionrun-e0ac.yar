rule TTP_XOR_QUAD_CurrentVersionRun_e0ac {
  strings:
    $key_e0ac = { b3 c3 [2] 97 cd [2] bc e1 [2] 92 c3 [2] 86 d8 [2] 89 c2 [2] 97 df [2] 95 de [2] 8e d8 [2] 92 df [2] 8e f0 }

  condition:
    any of them
}