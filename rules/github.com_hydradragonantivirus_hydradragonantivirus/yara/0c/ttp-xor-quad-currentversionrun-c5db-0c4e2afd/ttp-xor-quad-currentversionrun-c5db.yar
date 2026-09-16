rule TTP_XOR_QUAD_CurrentVersionRun_c5db {
  strings:
    $key_c5db = { 96 b4 [2] b2 ba [2] 99 96 [2] b7 b4 [2] a3 af [2] ac b5 [2] b2 a8 [2] b0 a9 [2] ab af [2] b7 a8 [2] ab 87 }

  condition:
    any of them
}