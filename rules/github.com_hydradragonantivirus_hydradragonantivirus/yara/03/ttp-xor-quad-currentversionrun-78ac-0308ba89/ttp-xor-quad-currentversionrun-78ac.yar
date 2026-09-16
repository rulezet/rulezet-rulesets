rule TTP_XOR_QUAD_CurrentVersionRun_78ac {
  strings:
    $key_78ac = { 2b c3 [2] 0f cd [2] 24 e1 [2] 0a c3 [2] 1e d8 [2] 11 c2 [2] 0f df [2] 0d de [2] 16 d8 [2] 0a df [2] 16 f0 }

  condition:
    any of them
}