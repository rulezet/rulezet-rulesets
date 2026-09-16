rule TTP_XOR_QUAD_CurrentVersionRun_dd89 {
  strings:
    $key_dd89 = { 8e e6 [2] aa e8 [2] 81 c4 [2] af e6 [2] bb fd [2] b4 e7 [2] aa fa [2] a8 fb [2] b3 fd [2] af fa [2] b3 d5 }

  condition:
    any of them
}