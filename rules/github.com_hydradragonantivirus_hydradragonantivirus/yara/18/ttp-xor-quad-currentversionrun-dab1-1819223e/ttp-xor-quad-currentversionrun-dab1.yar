rule TTP_XOR_QUAD_CurrentVersionRun_dab1 {
  strings:
    $key_dab1 = { 89 de [2] ad d0 [2] 86 fc [2] a8 de [2] bc c5 [2] b3 df [2] ad c2 [2] af c3 [2] b4 c5 [2] a8 c2 [2] b4 ed }

  condition:
    any of them
}