rule TTP_XOR_QUAD_CurrentVersionRun_3ab0 {
  strings:
    $key_3ab0 = { 69 df [2] 4d d1 [2] 66 fd [2] 48 df [2] 5c c4 [2] 53 de [2] 4d c3 [2] 4f c2 [2] 54 c4 [2] 48 c3 [2] 54 ec }

  condition:
    any of them
}