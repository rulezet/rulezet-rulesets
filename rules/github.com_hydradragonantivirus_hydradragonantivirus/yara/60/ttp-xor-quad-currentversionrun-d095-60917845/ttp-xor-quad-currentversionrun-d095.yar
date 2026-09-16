rule TTP_XOR_QUAD_CurrentVersionRun_d095 {
  strings:
    $key_d095 = { 83 fa [2] a7 f4 [2] 8c d8 [2] a2 fa [2] b6 e1 [2] b9 fb [2] a7 e6 [2] a5 e7 [2] be e1 [2] a2 e6 [2] be c9 }

  condition:
    any of them
}