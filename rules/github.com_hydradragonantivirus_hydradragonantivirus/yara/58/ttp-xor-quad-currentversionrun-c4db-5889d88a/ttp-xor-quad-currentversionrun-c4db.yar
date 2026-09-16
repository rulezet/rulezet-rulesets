rule TTP_XOR_QUAD_CurrentVersionRun_c4db {
  strings:
    $key_c4db = { 97 b4 [2] b3 ba [2] 98 96 [2] b6 b4 [2] a2 af [2] ad b5 [2] b3 a8 [2] b1 a9 [2] aa af [2] b6 a8 [2] aa 87 }

  condition:
    any of them
}