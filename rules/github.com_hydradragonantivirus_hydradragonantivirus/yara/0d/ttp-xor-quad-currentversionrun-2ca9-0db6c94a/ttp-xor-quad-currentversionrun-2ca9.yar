rule TTP_XOR_QUAD_CurrentVersionRun_2ca9 {
  strings:
    $key_2ca9 = { 7f c6 [2] 5b c8 [2] 70 e4 [2] 5e c6 [2] 4a dd [2] 45 c7 [2] 5b da [2] 59 db [2] 42 dd [2] 5e da [2] 42 f5 }

  condition:
    any of them
}