rule TTP_XOR_QUAD_CurrentVersionRun_28b5 {
  strings:
    $key_28b5 = { 7b da [2] 5f d4 [2] 74 f8 [2] 5a da [2] 4e c1 [2] 41 db [2] 5f c6 [2] 5d c7 [2] 46 c1 [2] 5a c6 [2] 46 e9 }

  condition:
    any of them
}