rule TTP_XOR_QUAD_CurrentVersionRun_27b1 {
  strings:
    $key_27b1 = { 74 de [2] 50 d0 [2] 7b fc [2] 55 de [2] 41 c5 [2] 4e df [2] 50 c2 [2] 52 c3 [2] 49 c5 [2] 55 c2 [2] 49 ed }

  condition:
    any of them
}