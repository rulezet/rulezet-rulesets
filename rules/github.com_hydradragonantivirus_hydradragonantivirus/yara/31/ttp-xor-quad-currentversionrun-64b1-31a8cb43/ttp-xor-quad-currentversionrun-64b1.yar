rule TTP_XOR_QUAD_CurrentVersionRun_64b1 {
  strings:
    $key_64b1 = { 37 de [2] 13 d0 [2] 38 fc [2] 16 de [2] 02 c5 [2] 0d df [2] 13 c2 [2] 11 c3 [2] 0a c5 [2] 16 c2 [2] 0a ed }

  condition:
    any of them
}