rule TTP_XOR_QUAD_CurrentVersionRun_2ab0 {
  strings:
    $key_2ab0 = { 79 df [2] 5d d1 [2] 76 fd [2] 58 df [2] 4c c4 [2] 43 de [2] 5d c3 [2] 5f c2 [2] 44 c4 [2] 58 c3 [2] 44 ec }

  condition:
    any of them
}