rule TTP_XOR_QUAD_CurrentVersionRun_c495 {
  strings:
    $key_c495 = { 97 fa [2] b3 f4 [2] 98 d8 [2] b6 fa [2] a2 e1 [2] ad fb [2] b3 e6 [2] b1 e7 [2] aa e1 [2] b6 e6 [2] aa c9 }

  condition:
    any of them
}