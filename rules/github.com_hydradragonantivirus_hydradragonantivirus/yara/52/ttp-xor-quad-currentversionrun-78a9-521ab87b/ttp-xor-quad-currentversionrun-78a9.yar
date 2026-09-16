rule TTP_XOR_QUAD_CurrentVersionRun_78a9 {
  strings:
    $key_78a9 = { 2b c6 [2] 0f c8 [2] 24 e4 [2] 0a c6 [2] 1e dd [2] 11 c7 [2] 0f da [2] 0d db [2] 16 dd [2] 0a da [2] 16 f5 }

  condition:
    any of them
}