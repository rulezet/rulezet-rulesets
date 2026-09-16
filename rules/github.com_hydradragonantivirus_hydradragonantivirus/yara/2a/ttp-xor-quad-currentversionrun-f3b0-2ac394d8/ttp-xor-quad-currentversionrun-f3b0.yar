rule TTP_XOR_QUAD_CurrentVersionRun_f3b0 {
  strings:
    $key_f3b0 = { a0 df [2] 84 d1 [2] af fd [2] 81 df [2] 95 c4 [2] 9a de [2] 84 c3 [2] 86 c2 [2] 9d c4 [2] 81 c3 [2] 9d ec }

  condition:
    any of them
}