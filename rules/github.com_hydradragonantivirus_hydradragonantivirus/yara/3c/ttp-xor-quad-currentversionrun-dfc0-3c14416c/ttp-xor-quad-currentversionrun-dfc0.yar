rule TTP_XOR_QUAD_CurrentVersionRun_dfc0 {
  strings:
    $key_dfc0 = { 8c af [2] a8 a1 [2] 83 8d [2] ad af [2] b9 b4 [2] b6 ae [2] a8 b3 [2] aa b2 [2] b1 b4 [2] ad b3 [2] b1 9c }

  condition:
    any of them
}