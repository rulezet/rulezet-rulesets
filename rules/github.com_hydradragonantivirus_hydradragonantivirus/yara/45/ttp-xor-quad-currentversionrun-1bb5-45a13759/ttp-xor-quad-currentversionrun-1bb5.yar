rule TTP_XOR_QUAD_CurrentVersionRun_1bb5 {
  strings:
    $key_1bb5 = { 48 da [2] 6c d4 [2] 47 f8 [2] 69 da [2] 7d c1 [2] 72 db [2] 6c c6 [2] 6e c7 [2] 75 c1 [2] 69 c6 [2] 75 e9 }

  condition:
    any of them
}