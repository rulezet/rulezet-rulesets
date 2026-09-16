rule TTP_XOR_QUAD_CurrentVersionRun_09b5 {
  strings:
    $key_09b5 = { 5a da [2] 7e d4 [2] 55 f8 [2] 7b da [2] 6f c1 [2] 60 db [2] 7e c6 [2] 7c c7 [2] 67 c1 [2] 7b c6 [2] 67 e9 }

  condition:
    any of them
}