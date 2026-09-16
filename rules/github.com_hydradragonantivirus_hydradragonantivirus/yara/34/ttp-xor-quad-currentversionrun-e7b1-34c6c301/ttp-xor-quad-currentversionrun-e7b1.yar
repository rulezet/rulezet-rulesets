rule TTP_XOR_QUAD_CurrentVersionRun_e7b1 {
  strings:
    $key_e7b1 = { b4 de [2] 90 d0 [2] bb fc [2] 95 de [2] 81 c5 [2] 8e df [2] 90 c2 [2] 92 c3 [2] 89 c5 [2] 95 c2 [2] 89 ed }

  condition:
    any of them
}