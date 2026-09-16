rule TTP_XOR_QUAD_CurrentVersionRun_6cad {
  strings:
    $key_6cad = { 3f c2 [2] 1b cc [2] 30 e0 [2] 1e c2 [2] 0a d9 [2] 05 c3 [2] 1b de [2] 19 df [2] 02 d9 [2] 1e de [2] 02 f1 }

  condition:
    any of them
}