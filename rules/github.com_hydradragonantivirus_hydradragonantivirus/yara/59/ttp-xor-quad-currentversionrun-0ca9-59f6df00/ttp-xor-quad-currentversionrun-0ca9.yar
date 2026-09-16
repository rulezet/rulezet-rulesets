rule TTP_XOR_QUAD_CurrentVersionRun_0ca9 {
  strings:
    $key_0ca9 = { 5f c6 [2] 7b c8 [2] 50 e4 [2] 7e c6 [2] 6a dd [2] 65 c7 [2] 7b da [2] 79 db [2] 62 dd [2] 7e da [2] 62 f5 }

  condition:
    any of them
}