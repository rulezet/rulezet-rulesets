rule TTP_XOR_QUAD_CurrentVersionRun_c6db {
  strings:
    $key_c6db = { 95 b4 [2] b1 ba [2] 9a 96 [2] b4 b4 [2] a0 af [2] af b5 [2] b1 a8 [2] b3 a9 [2] a8 af [2] b4 a8 [2] a8 87 }

  condition:
    any of them
}