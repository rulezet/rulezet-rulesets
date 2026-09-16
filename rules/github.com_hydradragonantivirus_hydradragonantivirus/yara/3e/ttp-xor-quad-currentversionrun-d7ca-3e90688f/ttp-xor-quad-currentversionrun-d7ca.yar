rule TTP_XOR_QUAD_CurrentVersionRun_d7ca {
  strings:
    $key_d7ca = { 84 a5 [2] a0 ab [2] 8b 87 [2] a5 a5 [2] b1 be [2] be a4 [2] a0 b9 [2] a2 b8 [2] b9 be [2] a5 b9 [2] b9 96 }

  condition:
    any of them
}