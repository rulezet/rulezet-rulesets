rule TTP_XOR_QUAD_CurrentVersionRun_4cad {
  strings:
    $key_4cad = { 1f c2 [2] 3b cc [2] 10 e0 [2] 3e c2 [2] 2a d9 [2] 25 c3 [2] 3b de [2] 39 df [2] 22 d9 [2] 3e de [2] 22 f1 }

  condition:
    any of them
}