rule TTP_XOR_QUAD_CurrentVersionRun_77af {
  strings:
    $key_77af = { 24 c0 [2] 00 ce [2] 2b e2 [2] 05 c0 [2] 11 db [2] 1e c1 [2] 00 dc [2] 02 dd [2] 19 db [2] 05 dc [2] 19 f3 }

  condition:
    any of them
}