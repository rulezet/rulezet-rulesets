rule TTP_XOR_QUAD_CurrentVersionRun_c294 {
  strings:
    $key_c294 = { 91 fb [2] b5 f5 [2] 9e d9 [2] b0 fb [2] a4 e0 [2] ab fa [2] b5 e7 [2] b7 e6 [2] ac e0 [2] b0 e7 [2] ac c8 }

  condition:
    any of them
}