rule TTP_XOR_QUAD_CurrentVersionRun_c6e4 {
  strings:
    $key_c6e4 = { 95 8b [2] b1 85 [2] 9a a9 [2] b4 8b [2] a0 90 [2] af 8a [2] b1 97 [2] b3 96 [2] a8 90 [2] b4 97 [2] a8 b8 }

  condition:
    any of them
}