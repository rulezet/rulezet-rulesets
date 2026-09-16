rule TTP_XOR_QUAD_CurrentVersionRun_29b4 {
  strings:
    $key_29b4 = { 7a db [2] 5e d5 [2] 75 f9 [2] 5b db [2] 4f c0 [2] 40 da [2] 5e c7 [2] 5c c6 [2] 47 c0 [2] 5b c7 [2] 47 e8 }

  condition:
    any of them
}