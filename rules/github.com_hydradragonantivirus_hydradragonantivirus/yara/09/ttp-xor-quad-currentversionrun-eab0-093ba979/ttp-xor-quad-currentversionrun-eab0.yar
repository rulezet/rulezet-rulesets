rule TTP_XOR_QUAD_CurrentVersionRun_eab0 {
  strings:
    $key_eab0 = { b9 df [2] 9d d1 [2] b6 fd [2] 98 df [2] 8c c4 [2] 83 de [2] 9d c3 [2] 9f c2 [2] 84 c4 [2] 98 c3 [2] 84 ec }

  condition:
    any of them
}