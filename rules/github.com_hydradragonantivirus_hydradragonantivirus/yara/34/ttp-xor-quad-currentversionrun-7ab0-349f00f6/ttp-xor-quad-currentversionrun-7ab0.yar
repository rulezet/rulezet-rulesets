rule TTP_XOR_QUAD_CurrentVersionRun_7ab0 {
  strings:
    $key_7ab0 = { 29 df [2] 0d d1 [2] 26 fd [2] 08 df [2] 1c c4 [2] 13 de [2] 0d c3 [2] 0f c2 [2] 14 c4 [2] 08 c3 [2] 14 ec }

  condition:
    any of them
}