rule TTP_XOR_QUAD_CurrentVersionRun_26b0 {
  strings:
    $key_26b0 = { 75 df [2] 51 d1 [2] 7a fd [2] 54 df [2] 40 c4 [2] 4f de [2] 51 c3 [2] 53 c2 [2] 48 c4 [2] 54 c3 [2] 48 ec }

  condition:
    any of them
}