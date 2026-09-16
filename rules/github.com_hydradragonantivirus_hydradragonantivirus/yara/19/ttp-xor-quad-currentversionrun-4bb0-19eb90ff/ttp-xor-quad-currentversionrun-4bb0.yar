rule TTP_XOR_QUAD_CurrentVersionRun_4bb0 {
  strings:
    $key_4bb0 = { 18 df [2] 3c d1 [2] 17 fd [2] 39 df [2] 2d c4 [2] 22 de [2] 3c c3 [2] 3e c2 [2] 25 c4 [2] 39 c3 [2] 25 ec }

  condition:
    any of them
}