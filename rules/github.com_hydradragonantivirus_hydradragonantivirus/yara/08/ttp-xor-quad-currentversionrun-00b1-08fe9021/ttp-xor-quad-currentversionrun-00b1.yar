rule TTP_XOR_QUAD_CurrentVersionRun_00b1 {
  strings:
    $key_00b1 = { 53 de [2] 77 d0 [2] 5c fc [2] 72 de [2] 66 c5 [2] 69 df [2] 77 c2 [2] 75 c3 [2] 6e c5 [2] 72 c2 [2] 6e ed }

  condition:
    any of them
}