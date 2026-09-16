rule TTP_XOR_QUAD_CurrentVersionRun_39b5 {
  strings:
    $key_39b5 = { 6a da [2] 4e d4 [2] 65 f8 [2] 4b da [2] 5f c1 [2] 50 db [2] 4e c6 [2] 4c c7 [2] 57 c1 [2] 4b c6 [2] 57 e9 }

  condition:
    any of them
}