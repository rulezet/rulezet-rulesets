rule TTP_XOR_QUAD_CurrentVersionRun_20b1 {
  strings:
    $key_20b1 = { 73 de [2] 57 d0 [2] 7c fc [2] 52 de [2] 46 c5 [2] 49 df [2] 57 c2 [2] 55 c3 [2] 4e c5 [2] 52 c2 [2] 4e ed }

  condition:
    any of them
}