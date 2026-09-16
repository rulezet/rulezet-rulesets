rule TTP_XOR_QUAD_CurrentVersionRun_c6c0 {
  strings:
    $key_c6c0 = { 95 af [2] b1 a1 [2] 9a 8d [2] b4 af [2] a0 b4 [2] af ae [2] b1 b3 [2] b3 b2 [2] a8 b4 [2] b4 b3 [2] a8 9c }

  condition:
    any of them
}