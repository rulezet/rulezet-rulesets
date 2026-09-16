rule TTP_XOR_QUAD_CurrentVersionRun_59b4 {
  strings:
    $key_59b4 = { 0a db [2] 2e d5 [2] 05 f9 [2] 2b db [2] 3f c0 [2] 30 da [2] 2e c7 [2] 2c c6 [2] 37 c0 [2] 2b c7 [2] 37 e8 }

  condition:
    any of them
}