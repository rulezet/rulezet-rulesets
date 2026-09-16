rule TTP_XOR_QUAD_CurrentVersionRun_d1b5 {
  strings:
    $key_d1b5 = { 82 da [2] a6 d4 [2] 8d f8 [2] a3 da [2] b7 c1 [2] b8 db [2] a6 c6 [2] a4 c7 [2] bf c1 [2] a3 c6 [2] bf e9 }

  condition:
    any of them
}