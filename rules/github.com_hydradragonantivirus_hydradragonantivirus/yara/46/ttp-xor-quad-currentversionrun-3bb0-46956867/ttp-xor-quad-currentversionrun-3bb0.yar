rule TTP_XOR_QUAD_CurrentVersionRun_3bb0 {
  strings:
    $key_3bb0 = { 68 df [2] 4c d1 [2] 67 fd [2] 49 df [2] 5d c4 [2] 52 de [2] 4c c3 [2] 4e c2 [2] 55 c4 [2] 49 c3 [2] 55 ec }

  condition:
    any of them
}