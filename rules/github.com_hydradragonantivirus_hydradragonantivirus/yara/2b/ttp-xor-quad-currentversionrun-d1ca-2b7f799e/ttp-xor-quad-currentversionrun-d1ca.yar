rule TTP_XOR_QUAD_CurrentVersionRun_d1ca {
  strings:
    $key_d1ca = { 82 a5 [2] a6 ab [2] 8d 87 [2] a3 a5 [2] b7 be [2] b8 a4 [2] a6 b9 [2] a4 b8 [2] bf be [2] a3 b9 [2] bf 96 }

  condition:
    any of them
}