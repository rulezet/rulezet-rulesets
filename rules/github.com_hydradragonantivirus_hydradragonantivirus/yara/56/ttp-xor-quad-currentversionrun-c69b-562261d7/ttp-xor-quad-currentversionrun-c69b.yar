rule TTP_XOR_QUAD_CurrentVersionRun_c69b {
  strings:
    $key_c69b = { 95 f4 [2] b1 fa [2] 9a d6 [2] b4 f4 [2] a0 ef [2] af f5 [2] b1 e8 [2] b3 e9 [2] a8 ef [2] b4 e8 [2] a8 c7 }

  condition:
    any of them
}