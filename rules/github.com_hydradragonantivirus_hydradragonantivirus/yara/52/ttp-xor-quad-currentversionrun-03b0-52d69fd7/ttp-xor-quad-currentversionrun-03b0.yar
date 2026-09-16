rule TTP_XOR_QUAD_CurrentVersionRun_03b0 {
  strings:
    $key_03b0 = { 50 df [2] 74 d1 [2] 5f fd [2] 71 df [2] 65 c4 [2] 6a de [2] 74 c3 [2] 76 c2 [2] 6d c4 [2] 71 c3 [2] 6d ec }

  condition:
    any of them
}