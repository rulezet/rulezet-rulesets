rule TTP_XOR_QUAD_CurrentVersionRun_22b0 {
  strings:
    $key_22b0 = { 71 df [2] 55 d1 [2] 7e fd [2] 50 df [2] 44 c4 [2] 4b de [2] 55 c3 [2] 57 c2 [2] 4c c4 [2] 50 c3 [2] 4c ec }

  condition:
    any of them
}