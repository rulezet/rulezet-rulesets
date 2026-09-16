rule TTP_XOR_QUAD_CurrentVersionRun_77b1 {
  strings:
    $key_77b1 = { 24 de [2] 00 d0 [2] 2b fc [2] 05 de [2] 11 c5 [2] 1e df [2] 00 c2 [2] 02 c3 [2] 19 c5 [2] 05 c2 [2] 19 ed }

  condition:
    any of them
}