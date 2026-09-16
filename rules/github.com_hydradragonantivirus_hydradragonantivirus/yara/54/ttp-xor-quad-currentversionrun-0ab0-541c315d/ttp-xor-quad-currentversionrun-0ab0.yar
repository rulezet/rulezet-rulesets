rule TTP_XOR_QUAD_CurrentVersionRun_0ab0 {
  strings:
    $key_0ab0 = { 59 df [2] 7d d1 [2] 56 fd [2] 78 df [2] 6c c4 [2] 63 de [2] 7d c3 [2] 7f c2 [2] 64 c4 [2] 78 c3 [2] 64 ec }

  condition:
    any of them
}