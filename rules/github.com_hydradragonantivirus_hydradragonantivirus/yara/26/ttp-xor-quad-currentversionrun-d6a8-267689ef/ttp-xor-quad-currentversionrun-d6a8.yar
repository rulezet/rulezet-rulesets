rule TTP_XOR_QUAD_CurrentVersionRun_d6a8 {
  strings:
    $key_d6a8 = { 85 c7 [2] a1 c9 [2] 8a e5 [2] a4 c7 [2] b0 dc [2] bf c6 [2] a1 db [2] a3 da [2] b8 dc [2] a4 db [2] b8 f4 }

  condition:
    any of them
}