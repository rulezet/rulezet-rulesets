rule TTP_XOR_QUAD_CurrentVersionRun_c6d7 {
  strings:
    $key_c6d7 = { 95 b8 [2] b1 b6 [2] 9a 9a [2] b4 b8 [2] a0 a3 [2] af b9 [2] b1 a4 [2] b3 a5 [2] a8 a3 [2] b4 a4 [2] a8 8b }

  condition:
    any of them
}