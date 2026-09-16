rule TTP_XOR_QUAD_CurrentVersionRun_d6c0 {
  strings:
    $key_d6c0 = { 85 af [2] a1 a1 [2] 8a 8d [2] a4 af [2] b0 b4 [2] bf ae [2] a1 b3 [2] a3 b2 [2] b8 b4 [2] a4 b3 [2] b8 9c }

  condition:
    any of them
}