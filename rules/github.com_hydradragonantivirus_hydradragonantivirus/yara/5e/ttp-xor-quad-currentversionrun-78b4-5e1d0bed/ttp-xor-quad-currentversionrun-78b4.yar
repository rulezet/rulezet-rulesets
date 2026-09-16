rule TTP_XOR_QUAD_CurrentVersionRun_78b4 {
  strings:
    $key_78b4 = { 2b db [2] 0f d5 [2] 24 f9 [2] 0a db [2] 1e c0 [2] 11 da [2] 0f c7 [2] 0d c6 [2] 16 c0 [2] 0a c7 [2] 16 e8 }

  condition:
    any of them
}