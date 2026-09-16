rule TTP_XOR_QUAD_CurrentVersionRun_74af {
  strings:
    $key_74af = { 27 c0 [2] 03 ce [2] 28 e2 [2] 06 c0 [2] 12 db [2] 1d c1 [2] 03 dc [2] 01 dd [2] 1a db [2] 06 dc [2] 1a f3 }

  condition:
    any of them
}