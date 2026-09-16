rule TTP_XOR_QUAD_CurrentVersionRun_79a9 {
  strings:
    $key_79a9 = { 2a c6 [2] 0e c8 [2] 25 e4 [2] 0b c6 [2] 1f dd [2] 10 c7 [2] 0e da [2] 0c db [2] 17 dd [2] 0b da [2] 17 f5 }

  condition:
    any of them
}