rule TTP_XOR_QUAD_CurrentVersionRun_70b1 {
  strings:
    $key_70b1 = { 23 de [2] 07 d0 [2] 2c fc [2] 02 de [2] 16 c5 [2] 19 df [2] 07 c2 [2] 05 c3 [2] 1e c5 [2] 02 c2 [2] 1e ed }

  condition:
    any of them
}