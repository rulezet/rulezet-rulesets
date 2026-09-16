rule TTP_XOR_QUAD_CurrentVersionRun_d6ca {
  strings:
    $key_d6ca = { 85 a5 [2] a1 ab [2] 8a 87 [2] a4 a5 [2] b0 be [2] bf a4 [2] a1 b9 [2] a3 b8 [2] b8 be [2] a4 b9 [2] b8 96 }

  condition:
    any of them
}