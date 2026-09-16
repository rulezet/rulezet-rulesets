rule TTP_XOR_QUAD_CurrentVersionRun_ecad {
  strings:
    $key_ecad = { bf c2 [2] 9b cc [2] b0 e0 [2] 9e c2 [2] 8a d9 [2] 85 c3 [2] 9b de [2] 99 df [2] 82 d9 [2] 9e de [2] 82 f1 }

  condition:
    any of them
}