rule TTP_XOR_QUAD_CurrentVersionRun_f9b5 {
  strings:
    $key_f9b5 = { aa da [2] 8e d4 [2] a5 f8 [2] 8b da [2] 9f c1 [2] 90 db [2] 8e c6 [2] 8c c7 [2] 97 c1 [2] 8b c6 [2] 97 e9 }

  condition:
    any of them
}