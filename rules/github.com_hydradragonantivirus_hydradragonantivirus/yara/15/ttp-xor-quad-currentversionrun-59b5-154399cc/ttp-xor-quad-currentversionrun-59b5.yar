rule TTP_XOR_QUAD_CurrentVersionRun_59b5 {
  strings:
    $key_59b5 = { 0a da [2] 2e d4 [2] 05 f8 [2] 2b da [2] 3f c1 [2] 30 db [2] 2e c6 [2] 2c c7 [2] 37 c1 [2] 2b c6 [2] 37 e9 }

  condition:
    any of them
}