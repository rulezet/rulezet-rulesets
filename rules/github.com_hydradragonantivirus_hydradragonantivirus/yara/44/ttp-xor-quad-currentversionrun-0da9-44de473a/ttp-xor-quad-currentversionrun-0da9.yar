rule TTP_XOR_QUAD_CurrentVersionRun_0da9 {
  strings:
    $key_0da9 = { 5e c6 [2] 7a c8 [2] 51 e4 [2] 7f c6 [2] 6b dd [2] 64 c7 [2] 7a da [2] 78 db [2] 63 dd [2] 7f da [2] 63 f5 }

  condition:
    any of them
}