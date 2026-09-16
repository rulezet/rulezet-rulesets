rule TTP_XOR_QUAD_CurrentVersionRun_e9b5 {
  strings:
    $key_e9b5 = { ba da [2] 9e d4 [2] b5 f8 [2] 9b da [2] 8f c1 [2] 80 db [2] 9e c6 [2] 9c c7 [2] 87 c1 [2] 9b c6 [2] 87 e9 }

  condition:
    any of them
}