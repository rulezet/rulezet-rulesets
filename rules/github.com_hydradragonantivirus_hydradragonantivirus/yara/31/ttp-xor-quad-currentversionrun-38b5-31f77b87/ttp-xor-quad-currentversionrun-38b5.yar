rule TTP_XOR_QUAD_CurrentVersionRun_38b5 {
  strings:
    $key_38b5 = { 6b da [2] 4f d4 [2] 64 f8 [2] 4a da [2] 5e c1 [2] 51 db [2] 4f c6 [2] 4d c7 [2] 56 c1 [2] 4a c6 [2] 56 e9 }

  condition:
    any of them
}