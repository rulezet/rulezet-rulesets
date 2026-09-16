rule TTP_XOR_QUAD_CurrentVersionRun_68a9 {
  strings:
    $key_68a9 = { 3b c6 [2] 1f c8 [2] 34 e4 [2] 1a c6 [2] 0e dd [2] 01 c7 [2] 1f da [2] 1d db [2] 06 dd [2] 1a da [2] 06 f5 }

  condition:
    any of them
}