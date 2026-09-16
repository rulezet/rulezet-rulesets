rule TTP_XOR_QUAD_CurrentVersionRun_c1c6 {
  strings:
    $key_c1c6 = { 92 a9 [2] b6 a7 [2] 9d 8b [2] b3 a9 [2] a7 b2 [2] a8 a8 [2] b6 b5 [2] b4 b4 [2] af b2 [2] b3 b5 [2] af 9a }

  condition:
    any of them
}