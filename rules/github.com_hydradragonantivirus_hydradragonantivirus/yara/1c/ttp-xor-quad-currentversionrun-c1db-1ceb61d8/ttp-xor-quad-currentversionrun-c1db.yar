rule TTP_XOR_QUAD_CurrentVersionRun_c1db {
  strings:
    $key_c1db = { 92 b4 [2] b6 ba [2] 9d 96 [2] b3 b4 [2] a7 af [2] a8 b5 [2] b6 a8 [2] b4 a9 [2] af af [2] b3 a8 [2] af 87 }

  condition:
    any of them
}