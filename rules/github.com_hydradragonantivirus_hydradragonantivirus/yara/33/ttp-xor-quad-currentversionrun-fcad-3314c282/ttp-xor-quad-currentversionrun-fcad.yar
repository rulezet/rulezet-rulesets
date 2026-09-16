rule TTP_XOR_QUAD_CurrentVersionRun_fcad {
  strings:
    $key_fcad = { af c2 [2] 8b cc [2] a0 e0 [2] 8e c2 [2] 9a d9 [2] 95 c3 [2] 8b de [2] 89 df [2] 92 d9 [2] 8e de [2] 92 f1 }

  condition:
    any of them
}