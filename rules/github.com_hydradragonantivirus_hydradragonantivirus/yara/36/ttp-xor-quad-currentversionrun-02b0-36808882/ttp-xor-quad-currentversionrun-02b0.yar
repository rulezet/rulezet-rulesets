rule TTP_XOR_QUAD_CurrentVersionRun_02b0 {
  strings:
    $key_02b0 = { 51 df [2] 75 d1 [2] 5e fd [2] 70 df [2] 64 c4 [2] 6b de [2] 75 c3 [2] 77 c2 [2] 6c c4 [2] 70 c3 [2] 6c ec }

  condition:
    any of them
}