rule TTP_XOR_QUAD_CurrentVersionRun_74b1 {
  strings:
    $key_74b1 = { 27 de [2] 03 d0 [2] 28 fc [2] 06 de [2] 12 c5 [2] 1d df [2] 03 c2 [2] 01 c3 [2] 1a c5 [2] 06 c2 [2] 1a ed }

  condition:
    any of them
}