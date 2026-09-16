rule TTP_XOR_QUAD_CurrentVersionRun_52b0 {
  strings:
    $key_52b0 = { 01 df [2] 25 d1 [2] 0e fd [2] 20 df [2] 34 c4 [2] 3b de [2] 25 c3 [2] 27 c2 [2] 3c c4 [2] 20 c3 [2] 3c ec }

  condition:
    any of them
}