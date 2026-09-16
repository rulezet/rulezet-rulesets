rule TTP_XOR_QUAD_CurrentVersionRun_d1a9 {
  strings:
    $key_d1a9 = { 82 c6 [2] a6 c8 [2] 8d e4 [2] a3 c6 [2] b7 dd [2] b8 c7 [2] a6 da [2] a4 db [2] bf dd [2] a3 da [2] bf f5 }

  condition:
    any of them
}