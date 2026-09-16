rule TTP_XOR_QUAD_CurrentVersionRun_47b1 {
  strings:
    $key_47b1 = { 14 de [2] 30 d0 [2] 1b fc [2] 35 de [2] 21 c5 [2] 2e df [2] 30 c2 [2] 32 c3 [2] 29 c5 [2] 35 c2 [2] 29 ed }

  condition:
    any of them
}