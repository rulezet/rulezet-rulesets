rule TTP_XOR_QUAD_CurrentVersionRun_d197 {
  strings:
    $key_d197 = { 82 f8 [2] a6 f6 [2] 8d da [2] a3 f8 [2] b7 e3 [2] b8 f9 [2] a6 e4 [2] a4 e5 [2] bf e3 [2] a3 e4 [2] bf cb }

  condition:
    any of them
}