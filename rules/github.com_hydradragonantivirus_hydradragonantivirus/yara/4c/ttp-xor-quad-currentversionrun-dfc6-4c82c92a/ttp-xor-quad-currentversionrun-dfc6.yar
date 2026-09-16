rule TTP_XOR_QUAD_CurrentVersionRun_dfc6 {
  strings:
    $key_dfc6 = { 8c a9 [2] a8 a7 [2] 83 8b [2] ad a9 [2] b9 b2 [2] b6 a8 [2] a8 b5 [2] aa b4 [2] b1 b2 [2] ad b5 [2] b1 9a }

  condition:
    any of them
}