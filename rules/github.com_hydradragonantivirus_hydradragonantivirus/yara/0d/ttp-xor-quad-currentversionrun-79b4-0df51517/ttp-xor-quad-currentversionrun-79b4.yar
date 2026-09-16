rule TTP_XOR_QUAD_CurrentVersionRun_79b4 {
  strings:
    $key_79b4 = { 2a db [2] 0e d5 [2] 25 f9 [2] 0b db [2] 1f c0 [2] 10 da [2] 0e c7 [2] 0c c6 [2] 17 c0 [2] 0b c7 [2] 17 e8 }

  condition:
    any of them
}