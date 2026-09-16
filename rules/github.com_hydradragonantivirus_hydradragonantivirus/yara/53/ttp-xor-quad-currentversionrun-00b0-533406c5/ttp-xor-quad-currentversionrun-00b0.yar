rule TTP_XOR_QUAD_CurrentVersionRun_00b0 {
  strings:
    $key_00b0 = { 53 df [2] 77 d1 [2] 5c fd [2] 72 df [2] 66 c4 [2] 69 de [2] 77 c3 [2] 75 c2 [2] 6e c4 [2] 72 c3 [2] 6e ec }

  condition:
    any of them
}