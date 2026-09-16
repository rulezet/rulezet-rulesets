rule TTP_XOR_QUAD_CurrentVersionRun_d2b1 {
  strings:
    $key_d2b1 = { 81 de [2] a5 d0 [2] 8e fc [2] a0 de [2] b4 c5 [2] bb df [2] a5 c2 [2] a7 c3 [2] bc c5 [2] a0 c2 [2] bc ed }

  condition:
    any of them
}