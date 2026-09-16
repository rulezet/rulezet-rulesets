rule TTP_XOR_QUAD_CurrentVersionRun_55ac {
  strings:
    $key_55ac = { 06 c3 [2] 22 cd [2] 09 e1 [2] 27 c3 [2] 33 d8 [2] 3c c2 [2] 22 df [2] 20 de [2] 3b d8 [2] 27 df [2] 3b f0 }

  condition:
    any of them
}