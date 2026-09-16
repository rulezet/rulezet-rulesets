rule TTP_XOR_QUAD_CurrentVersionRun_c6c1 {
  strings:
    $key_c6c1 = { 95 ae [2] b1 a0 [2] 9a 8c [2] b4 ae [2] a0 b5 [2] af af [2] b1 b2 [2] b3 b3 [2] a8 b5 [2] b4 b2 [2] a8 9d }

  condition:
    any of them
}