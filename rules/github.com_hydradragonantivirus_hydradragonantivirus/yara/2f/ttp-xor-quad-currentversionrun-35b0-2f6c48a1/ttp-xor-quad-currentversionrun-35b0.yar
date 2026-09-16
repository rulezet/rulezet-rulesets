rule TTP_XOR_QUAD_CurrentVersionRun_35b0 {
  strings:
    $key_35b0 = { 66 df [2] 42 d1 [2] 69 fd [2] 47 df [2] 53 c4 [2] 5c de [2] 42 c3 [2] 40 c2 [2] 5b c4 [2] 47 c3 [2] 5b ec }

  condition:
    any of them
}