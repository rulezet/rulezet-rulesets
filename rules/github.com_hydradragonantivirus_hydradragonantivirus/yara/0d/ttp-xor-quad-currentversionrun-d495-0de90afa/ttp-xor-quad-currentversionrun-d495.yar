rule TTP_XOR_QUAD_CurrentVersionRun_d495 {
  strings:
    $key_d495 = { 87 fa [2] a3 f4 [2] 88 d8 [2] a6 fa [2] b2 e1 [2] bd fb [2] a3 e6 [2] a1 e7 [2] ba e1 [2] a6 e6 [2] ba c9 }

  condition:
    any of them
}