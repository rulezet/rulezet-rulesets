rule TTP_XOR_QUAD_CurrentVersionRun_10b1 {
  strings:
    $key_10b1 = { 43 de [2] 67 d0 [2] 4c fc [2] 62 de [2] 76 c5 [2] 79 df [2] 67 c2 [2] 65 c3 [2] 7e c5 [2] 62 c2 [2] 7e ed }

  condition:
    any of them
}