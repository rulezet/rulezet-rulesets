rule TTP_XOR_QUAD_CurrentVersionRun_76b0 {
  strings:
    $key_76b0 = { 25 df [2] 01 d1 [2] 2a fd [2] 04 df [2] 10 c4 [2] 1f de [2] 01 c3 [2] 03 c2 [2] 18 c4 [2] 04 c3 [2] 18 ec }

  condition:
    any of them
}