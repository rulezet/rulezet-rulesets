rule TTP_XOR_QUAD_CurrentVersionRun_52ad {
  strings:
    $key_52ad = { 01 c2 [2] 25 cc [2] 0e e0 [2] 20 c2 [2] 34 d9 [2] 3b c3 [2] 25 de [2] 27 df [2] 3c d9 [2] 20 de [2] 3c f1 }

  condition:
    any of them
}