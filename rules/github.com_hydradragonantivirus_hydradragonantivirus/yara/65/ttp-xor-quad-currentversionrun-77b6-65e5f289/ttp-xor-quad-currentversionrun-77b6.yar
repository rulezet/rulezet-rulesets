rule TTP_XOR_QUAD_CurrentVersionRun_77b6 {
  strings:
    $key_77b6 = { 24 d9 [2] 00 d7 [2] 2b fb [2] 05 d9 [2] 11 c2 [2] 1e d8 [2] 00 c5 [2] 02 c4 [2] 19 c2 [2] 05 c5 [2] 19 ea }

  condition:
    any of them
}