rule TTP_XOR_QUAD_CurrentVersionRun_18b5 {
  strings:
    $key_18b5 = { 4b da [2] 6f d4 [2] 44 f8 [2] 6a da [2] 7e c1 [2] 71 db [2] 6f c6 [2] 6d c7 [2] 76 c1 [2] 6a c6 [2] 76 e9 }

  condition:
    any of them
}