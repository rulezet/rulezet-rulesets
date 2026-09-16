rule TTP_XOR_QUAD_CurrentVersionRun_d689 {
  strings:
    $key_d689 = { 85 e6 [2] a1 e8 [2] 8a c4 [2] a4 e6 [2] b0 fd [2] bf e7 [2] a1 fa [2] a3 fb [2] b8 fd [2] a4 fa [2] b8 d5 }

  condition:
    any of them
}