rule TTP_XOR_QUAD_CurrentVersionRun_28a9 {
  strings:
    $key_28a9 = { 7b c6 [2] 5f c8 [2] 74 e4 [2] 5a c6 [2] 4e dd [2] 41 c7 [2] 5f da [2] 5d db [2] 46 dd [2] 5a da [2] 46 f5 }

  condition:
    any of them
}