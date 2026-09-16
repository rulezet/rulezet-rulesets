rule TTP_XOR_QUAD_CurrentVersionRun_d5b1 {
  strings:
    $key_d5b1 = { 86 de [2] a2 d0 [2] 89 fc [2] a7 de [2] b3 c5 [2] bc df [2] a2 c2 [2] a0 c3 [2] bb c5 [2] a7 c2 [2] bb ed }

  condition:
    any of them
}