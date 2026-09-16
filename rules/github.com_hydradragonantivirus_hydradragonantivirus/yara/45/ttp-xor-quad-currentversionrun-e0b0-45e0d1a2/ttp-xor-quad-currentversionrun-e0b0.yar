rule TTP_XOR_QUAD_CurrentVersionRun_e0b0 {
  strings:
    $key_e0b0 = { b3 df [2] 97 d1 [2] bc fd [2] 92 df [2] 86 c4 [2] 89 de [2] 97 c3 [2] 95 c2 [2] 8e c4 [2] 92 c3 [2] 8e ec }

  condition:
    any of them
}