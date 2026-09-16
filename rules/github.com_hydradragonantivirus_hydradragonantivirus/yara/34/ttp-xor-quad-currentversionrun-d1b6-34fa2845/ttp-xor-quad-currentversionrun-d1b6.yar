rule TTP_XOR_QUAD_CurrentVersionRun_d1b6 {
  strings:
    $key_d1b6 = { 82 d9 [2] a6 d7 [2] 8d fb [2] a3 d9 [2] b7 c2 [2] b8 d8 [2] a6 c5 [2] a4 c4 [2] bf c2 [2] a3 c5 [2] bf ea }

  condition:
    any of them
}