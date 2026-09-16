rule TTP_XOR_QUAD_CurrentVersionRun_40b1 {
  strings:
    $key_40b1 = { 13 de [2] 37 d0 [2] 1c fc [2] 32 de [2] 26 c5 [2] 29 df [2] 37 c2 [2] 35 c3 [2] 2e c5 [2] 32 c2 [2] 2e ed }

  condition:
    any of them
}