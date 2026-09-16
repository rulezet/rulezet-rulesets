rule TTP_XOR_QUAD_CurrentVersionRun_f7b0 {
  strings:
    $key_f7b0 = { a4 df [2] 80 d1 [2] ab fd [2] 85 df [2] 91 c4 [2] 9e de [2] 80 c3 [2] 82 c2 [2] 99 c4 [2] 85 c3 [2] 99 ec }

  condition:
    any of them
}