rule TTP_XOR_QUAD_CurrentVersionRun_68ac {
  strings:
    $key_68ac = { 3b c3 [2] 1f cd [2] 34 e1 [2] 1a c3 [2] 0e d8 [2] 01 c2 [2] 1f df [2] 1d de [2] 06 d8 [2] 1a df [2] 06 f0 }

  condition:
    any of them
}