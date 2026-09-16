rule TTP_XOR_QUAD_CurrentVersionRun_67b1 {
  strings:
    $key_67b1 = { 34 de [2] 10 d0 [2] 3b fc [2] 15 de [2] 01 c5 [2] 0e df [2] 10 c2 [2] 12 c3 [2] 09 c5 [2] 15 c2 [2] 09 ed }

  condition:
    any of them
}