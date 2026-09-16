rule TTP_XOR_QUAD_CurrentVersionRun_57b0 {
  strings:
    $key_57b0 = { 04 df [2] 20 d1 [2] 0b fd [2] 25 df [2] 31 c4 [2] 3e de [2] 20 c3 [2] 22 c2 [2] 39 c4 [2] 25 c3 [2] 39 ec }

  condition:
    any of them
}