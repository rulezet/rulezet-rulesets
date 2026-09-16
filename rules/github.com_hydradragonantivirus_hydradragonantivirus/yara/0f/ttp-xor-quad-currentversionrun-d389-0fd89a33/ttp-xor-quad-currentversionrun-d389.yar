rule TTP_XOR_QUAD_CurrentVersionRun_d389 {
  strings:
    $key_d389 = { 80 e6 [2] a4 e8 [2] 8f c4 [2] a1 e6 [2] b5 fd [2] ba e7 [2] a4 fa [2] a6 fb [2] bd fd [2] a1 fa [2] bd d5 }

  condition:
    any of them
}