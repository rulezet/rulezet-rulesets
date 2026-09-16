rule TTP_XOR_QUAD_CurrentVersionRun_ca94 {
  strings:
    $key_ca94 = { 99 fb [2] bd f5 [2] 96 d9 [2] b8 fb [2] ac e0 [2] a3 fa [2] bd e7 [2] bf e6 [2] a4 e0 [2] b8 e7 [2] a4 c8 }

  condition:
    any of them
}