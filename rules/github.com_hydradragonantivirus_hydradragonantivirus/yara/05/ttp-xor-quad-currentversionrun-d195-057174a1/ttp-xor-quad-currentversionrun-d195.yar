rule TTP_XOR_QUAD_CurrentVersionRun_d195 {
  strings:
    $key_d195 = { 82 fa [2] a6 f4 [2] 8d d8 [2] a3 fa [2] b7 e1 [2] b8 fb [2] a6 e6 [2] a4 e7 [2] bf e1 [2] a3 e6 [2] bf c9 }

  condition:
    any of them
}