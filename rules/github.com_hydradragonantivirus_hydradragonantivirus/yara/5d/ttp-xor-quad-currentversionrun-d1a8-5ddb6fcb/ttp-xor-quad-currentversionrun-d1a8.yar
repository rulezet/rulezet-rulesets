rule TTP_XOR_QUAD_CurrentVersionRun_d1a8 {
  strings:
    $key_d1a8 = { 82 c7 [2] a6 c9 [2] 8d e5 [2] a3 c7 [2] b7 dc [2] b8 c6 [2] a6 db [2] a4 da [2] bf dc [2] a3 db [2] bf f4 }

  condition:
    any of them
}