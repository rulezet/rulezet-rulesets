rule TTP_XOR_QUAD_CurrentVersionRun_f8a9 {
  strings:
    $key_f8a9 = { ab c6 [2] 8f c8 [2] a4 e4 [2] 8a c6 [2] 9e dd [2] 91 c7 [2] 8f da [2] 8d db [2] 96 dd [2] 8a da [2] 96 f5 }

  condition:
    any of them
}