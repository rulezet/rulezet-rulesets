rule TTP_XOR_QUAD_CurrentVersionRun_10b0 {
  strings:
    $key_10b0 = { 43 df [2] 67 d1 [2] 4c fd [2] 62 df [2] 76 c4 [2] 79 de [2] 67 c3 [2] 65 c2 [2] 7e c4 [2] 62 c3 [2] 7e ec }

  condition:
    any of them
}