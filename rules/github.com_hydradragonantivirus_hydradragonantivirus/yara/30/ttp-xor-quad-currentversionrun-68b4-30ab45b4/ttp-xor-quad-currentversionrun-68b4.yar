rule TTP_XOR_QUAD_CurrentVersionRun_68b4 {
  strings:
    $key_68b4 = { 3b db [2] 1f d5 [2] 34 f9 [2] 1a db [2] 0e c0 [2] 01 da [2] 1f c7 [2] 1d c6 [2] 06 c0 [2] 1a c7 [2] 06 e8 }

  condition:
    any of them
}