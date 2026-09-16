rule TTP_XOR_QUAD_CurrentVersionRun_f6b0 {
  strings:
    $key_f6b0 = { a5 df [2] 81 d1 [2] aa fd [2] 84 df [2] 90 c4 [2] 9f de [2] 81 c3 [2] 83 c2 [2] 98 c4 [2] 84 c3 [2] 98 ec }

  condition:
    any of them
}