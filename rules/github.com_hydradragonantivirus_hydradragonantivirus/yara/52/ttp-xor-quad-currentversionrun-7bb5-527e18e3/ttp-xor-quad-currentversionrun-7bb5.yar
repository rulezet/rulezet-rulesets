rule TTP_XOR_QUAD_CurrentVersionRun_7bb5 {
  strings:
    $key_7bb5 = { 28 da [2] 0c d4 [2] 27 f8 [2] 09 da [2] 1d c1 [2] 12 db [2] 0c c6 [2] 0e c7 [2] 15 c1 [2] 09 c6 [2] 15 e9 }

  condition:
    any of them
}