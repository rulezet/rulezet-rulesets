rule TTP_XOR_QUAD_CurrentVersionRun_78b5 {
  strings:
    $key_78b5 = { 2b da [2] 0f d4 [2] 24 f8 [2] 0a da [2] 1e c1 [2] 11 db [2] 0f c6 [2] 0d c7 [2] 16 c1 [2] 0a c6 [2] 16 e9 }

  condition:
    any of them
}