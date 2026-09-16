rule TTP_XOR_QUAD_CurrentVersionRun_60b1 {
  strings:
    $key_60b1 = { 33 de [2] 17 d0 [2] 3c fc [2] 12 de [2] 06 c5 [2] 09 df [2] 17 c2 [2] 15 c3 [2] 0e c5 [2] 12 c2 [2] 0e ed }

  condition:
    any of them
}