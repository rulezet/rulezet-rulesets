rule TTP_XOR_QUAD_CurrentVersionRun_36b0 {
  strings:
    $key_36b0 = { 65 df [2] 41 d1 [2] 6a fd [2] 44 df [2] 50 c4 [2] 5f de [2] 41 c3 [2] 43 c2 [2] 58 c4 [2] 44 c3 [2] 58 ec }

  condition:
    any of them
}