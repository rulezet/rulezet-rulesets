rule TTP_XOR_QUAD_CurrentVersionRun_e6a9 {
  strings:
    $key_e6a9 = { b5 c6 [2] 91 c8 [2] ba e4 [2] 94 c6 [2] 80 dd [2] 8f c7 [2] 91 da [2] 93 db [2] 88 dd [2] 94 da [2] 88 f5 }

  condition:
    any of them
}