rule TTP_XOR_QUAD_CurrentVersionRun_70af {
  strings:
    $key_70af = { 23 c0 [2] 07 ce [2] 2c e2 [2] 02 c0 [2] 16 db [2] 19 c1 [2] 07 dc [2] 05 dd [2] 1e db [2] 02 dc [2] 1e f3 }

  condition:
    any of them
}