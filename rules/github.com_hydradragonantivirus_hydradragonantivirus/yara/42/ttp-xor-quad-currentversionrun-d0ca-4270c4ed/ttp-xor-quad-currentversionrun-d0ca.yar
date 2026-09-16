rule TTP_XOR_QUAD_CurrentVersionRun_d0ca {
  strings:
    $key_d0ca = { 83 a5 [2] a7 ab [2] 8c 87 [2] a2 a5 [2] b6 be [2] b9 a4 [2] a7 b9 [2] a5 b8 [2] be be [2] a2 b9 [2] be 96 }

  condition:
    any of them
}