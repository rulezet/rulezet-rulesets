rule TTP_XOR_QUAD_CurrentVersionRun_d789 {
  strings:
    $key_d789 = { 84 e6 [2] a0 e8 [2] 8b c4 [2] a5 e6 [2] b1 fd [2] be e7 [2] a0 fa [2] a2 fb [2] b9 fd [2] a5 fa [2] b9 d5 }

  condition:
    any of them
}