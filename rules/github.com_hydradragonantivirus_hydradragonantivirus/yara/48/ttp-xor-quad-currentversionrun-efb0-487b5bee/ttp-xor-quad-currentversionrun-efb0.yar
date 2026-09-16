rule TTP_XOR_QUAD_CurrentVersionRun_efb0 {
  strings:
    $key_efb0 = { bc df [2] 98 d1 [2] b3 fd [2] 9d df [2] 89 c4 [2] 86 de [2] 98 c3 [2] 9a c2 [2] 81 c4 [2] 9d c3 [2] 81 ec }

  condition:
    any of them
}