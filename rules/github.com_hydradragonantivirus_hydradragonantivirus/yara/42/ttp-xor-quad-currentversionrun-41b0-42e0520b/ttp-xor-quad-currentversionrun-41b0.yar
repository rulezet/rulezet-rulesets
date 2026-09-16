rule TTP_XOR_QUAD_CurrentVersionRun_41b0 {
  strings:
    $key_41b0 = { 12 df [2] 36 d1 [2] 1d fd [2] 33 df [2] 27 c4 [2] 28 de [2] 36 c3 [2] 34 c2 [2] 2f c4 [2] 33 c3 [2] 2f ec }

  condition:
    any of them
}