rule TTP_XOR_QUAD_CurrentVersionRun_d6c1 {
  strings:
    $key_d6c1 = { 85 ae [2] a1 a0 [2] 8a 8c [2] a4 ae [2] b0 b5 [2] bf af [2] a1 b2 [2] a3 b3 [2] b8 b5 [2] a4 b2 [2] b8 9d }

  condition:
    any of them
}