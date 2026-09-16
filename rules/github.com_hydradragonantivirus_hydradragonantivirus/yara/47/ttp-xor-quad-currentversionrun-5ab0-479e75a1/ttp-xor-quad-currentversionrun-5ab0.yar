rule TTP_XOR_QUAD_CurrentVersionRun_5ab0 {
  strings:
    $key_5ab0 = { 09 df [2] 2d d1 [2] 06 fd [2] 28 df [2] 3c c4 [2] 33 de [2] 2d c3 [2] 2f c2 [2] 34 c4 [2] 28 c3 [2] 34 ec }

  condition:
    any of them
}