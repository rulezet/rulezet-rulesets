rule TTP_XOR_QUAD_CurrentVersionRun_e2b0 {
  strings:
    $key_e2b0 = { b1 df [2] 95 d1 [2] be fd [2] 90 df [2] 84 c4 [2] 8b de [2] 95 c3 [2] 97 c2 [2] 8c c4 [2] 90 c3 [2] 8c ec }

  condition:
    any of them
}