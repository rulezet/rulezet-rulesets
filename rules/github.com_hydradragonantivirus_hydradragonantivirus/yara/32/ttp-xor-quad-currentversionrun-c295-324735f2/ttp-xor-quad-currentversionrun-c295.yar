rule TTP_XOR_QUAD_CurrentVersionRun_c295 {
  strings:
    $key_c295 = { 91 fa [2] b5 f4 [2] 9e d8 [2] b0 fa [2] a4 e1 [2] ab fb [2] b5 e6 [2] b7 e7 [2] ac e1 [2] b0 e6 [2] ac c9 }

  condition:
    any of them
}