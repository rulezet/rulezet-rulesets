rule TTP_XOR_QUAD_CurrentVersionRun_c0db {
  strings:
    $key_c0db = { 93 b4 [2] b7 ba [2] 9c 96 [2] b2 b4 [2] a6 af [2] a9 b5 [2] b7 a8 [2] b5 a9 [2] ae af [2] b2 a8 [2] ae 87 }

  condition:
    any of them
}