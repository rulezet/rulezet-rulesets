rule TTP_XOR_QUAD_CurrentVersionRun_c1af {
  strings:
    $key_c1af = { 92 c0 [2] b6 ce [2] 9d e2 [2] b3 c0 [2] a7 db [2] a8 c1 [2] b6 dc [2] b4 dd [2] af db [2] b3 dc [2] af f3 }

  condition:
    any of them
}