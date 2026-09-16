rule TTP_XOR_QUAD_CurrentVersionRun_06b0 {
  strings:
    $key_06b0 = { 55 df [2] 71 d1 [2] 5a fd [2] 74 df [2] 60 c4 [2] 6f de [2] 71 c3 [2] 73 c2 [2] 68 c4 [2] 74 c3 [2] 68 ec }

  condition:
    any of them
}