rule TTP_XOR_QUAD_CurrentVersionRun_e8ac {
  strings:
    $key_e8ac = { bb c3 [2] 9f cd [2] b4 e1 [2] 9a c3 [2] 8e d8 [2] 81 c2 [2] 9f df [2] 9d de [2] 86 d8 [2] 9a df [2] 86 f0 }

  condition:
    any of them
}