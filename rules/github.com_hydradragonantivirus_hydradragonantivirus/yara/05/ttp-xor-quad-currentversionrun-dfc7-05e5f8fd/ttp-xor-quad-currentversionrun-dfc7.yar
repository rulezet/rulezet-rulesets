rule TTP_XOR_QUAD_CurrentVersionRun_dfc7 {
  strings:
    $key_dfc7 = { 8c a8 [2] a8 a6 [2] 83 8a [2] ad a8 [2] b9 b3 [2] b6 a9 [2] a8 b4 [2] aa b5 [2] b1 b3 [2] ad b4 [2] b1 9b }

  condition:
    any of them
}