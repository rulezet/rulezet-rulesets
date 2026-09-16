rule TTP_XOR_QUAD_CurrentVersionRun_44b1 {
  strings:
    $key_44b1 = { 17 de [2] 33 d0 [2] 18 fc [2] 36 de [2] 22 c5 [2] 2d df [2] 33 c2 [2] 31 c3 [2] 2a c5 [2] 36 c2 [2] 2a ed }

  condition:
    any of them
}