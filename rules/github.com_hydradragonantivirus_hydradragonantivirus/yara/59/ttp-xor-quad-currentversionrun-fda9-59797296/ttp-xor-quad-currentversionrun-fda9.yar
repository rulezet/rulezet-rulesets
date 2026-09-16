rule TTP_XOR_QUAD_CurrentVersionRun_fda9 {
  strings:
    $key_fda9 = { ae c6 [2] 8a c8 [2] a1 e4 [2] 8f c6 [2] 9b dd [2] 94 c7 [2] 8a da [2] 88 db [2] 93 dd [2] 8f da [2] 93 f5 }

  condition:
    any of them
}