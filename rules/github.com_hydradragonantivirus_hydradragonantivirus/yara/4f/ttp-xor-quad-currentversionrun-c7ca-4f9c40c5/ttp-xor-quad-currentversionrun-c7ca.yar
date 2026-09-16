rule TTP_XOR_QUAD_CurrentVersionRun_c7ca {
  strings:
    $key_c7ca = { 94 a5 [2] b0 ab [2] 9b 87 [2] b5 a5 [2] a1 be [2] ae a4 [2] b0 b9 [2] b2 b8 [2] a9 be [2] b5 b9 [2] a9 96 }

  condition:
    any of them
}