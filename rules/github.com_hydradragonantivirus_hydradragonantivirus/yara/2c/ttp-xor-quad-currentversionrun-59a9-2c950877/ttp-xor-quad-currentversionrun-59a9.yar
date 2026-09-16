rule TTP_XOR_QUAD_CurrentVersionRun_59a9 {
  strings:
    $key_59a9 = { 0a c6 [2] 2e c8 [2] 05 e4 [2] 2b c6 [2] 3f dd [2] 30 c7 [2] 2e da [2] 2c db [2] 37 dd [2] 2b da [2] 37 f5 }

  condition:
    any of them
}