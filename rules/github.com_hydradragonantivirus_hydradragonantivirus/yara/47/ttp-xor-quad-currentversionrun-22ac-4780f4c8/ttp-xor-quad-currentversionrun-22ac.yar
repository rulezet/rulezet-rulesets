rule TTP_XOR_QUAD_CurrentVersionRun_22ac {
  strings:
    $key_22ac = { 71 c3 [2] 55 cd [2] 7e e1 [2] 50 c3 [2] 44 d8 [2] 4b c2 [2] 55 df [2] 57 de [2] 4c d8 [2] 50 df [2] 4c f0 }

  condition:
    any of them
}