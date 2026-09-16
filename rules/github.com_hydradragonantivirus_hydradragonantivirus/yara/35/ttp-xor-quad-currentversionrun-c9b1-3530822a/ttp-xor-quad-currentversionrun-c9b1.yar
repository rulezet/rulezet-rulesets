rule TTP_XOR_QUAD_CurrentVersionRun_c9b1 {
  strings:
    $key_c9b1 = { 9a de [2] be d0 [2] 95 fc [2] bb de [2] af c5 [2] a0 df [2] be c2 [2] bc c3 [2] a7 c5 [2] bb c2 [2] a7 ed }

  condition:
    any of them
}