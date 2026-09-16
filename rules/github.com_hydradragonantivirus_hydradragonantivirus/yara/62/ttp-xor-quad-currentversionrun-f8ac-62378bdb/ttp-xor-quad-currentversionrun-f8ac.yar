rule TTP_XOR_QUAD_CurrentVersionRun_f8ac {
  strings:
    $key_f8ac = { ab c3 [2] 8f cd [2] a4 e1 [2] 8a c3 [2] 9e d8 [2] 91 c2 [2] 8f df [2] 8d de [2] 96 d8 [2] 8a df [2] 96 f0 }

  condition:
    any of them
}