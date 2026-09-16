rule TTP_XOR_QUAD_CurrentVersionRun_d594 {
  strings:
    $key_d594 = { 86 fb [2] a2 f5 [2] 89 d9 [2] a7 fb [2] b3 e0 [2] bc fa [2] a2 e7 [2] a0 e6 [2] bb e0 [2] a7 e7 [2] bb c8 }

  condition:
    any of them
}