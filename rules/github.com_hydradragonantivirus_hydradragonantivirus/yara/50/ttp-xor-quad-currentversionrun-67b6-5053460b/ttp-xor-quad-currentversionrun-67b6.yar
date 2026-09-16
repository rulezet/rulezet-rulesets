rule TTP_XOR_QUAD_CurrentVersionRun_67b6 {
  strings:
    $key_67b6 = { 34 d9 [2] 10 d7 [2] 3b fb [2] 15 d9 [2] 01 c2 [2] 0e d8 [2] 10 c5 [2] 12 c4 [2] 09 c2 [2] 15 c5 [2] 09 ea }

  condition:
    any of them
}