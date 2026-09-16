rule TTP_XOR_QUAD_CurrentVersionRun_d1af {
  strings:
    $key_d1af = { 82 c0 [2] a6 ce [2] 8d e2 [2] a3 c0 [2] b7 db [2] b8 c1 [2] a6 dc [2] a4 dd [2] bf db [2] a3 dc [2] bf f3 }

  condition:
    any of them
}