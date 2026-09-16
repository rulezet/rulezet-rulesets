rule TTP_XOR_QUAD_CurrentVersionRun_c6d6 {
  strings:
    $key_c6d6 = { 95 b9 [2] b1 b7 [2] 9a 9b [2] b4 b9 [2] a0 a2 [2] af b8 [2] b1 a5 [2] b3 a4 [2] a8 a2 [2] b4 a5 [2] a8 8a }

  condition:
    any of them
}