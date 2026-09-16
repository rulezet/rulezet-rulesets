rule TTP_XOR_QUAD_CurrentVersionRun_45b0 {
  strings:
    $key_45b0 = { 16 df [2] 32 d1 [2] 19 fd [2] 37 df [2] 23 c4 [2] 2c de [2] 32 c3 [2] 30 c2 [2] 2b c4 [2] 37 c3 [2] 2b ec }

  condition:
    any of them
}