rule TTP_XOR_QUAD_CurrentVersionRun_67af {
  strings:
    $key_67af = { 34 c0 [2] 10 ce [2] 3b e2 [2] 15 c0 [2] 01 db [2] 0e c1 [2] 10 dc [2] 12 dd [2] 09 db [2] 15 dc [2] 09 f3 }

  condition:
    any of them
}