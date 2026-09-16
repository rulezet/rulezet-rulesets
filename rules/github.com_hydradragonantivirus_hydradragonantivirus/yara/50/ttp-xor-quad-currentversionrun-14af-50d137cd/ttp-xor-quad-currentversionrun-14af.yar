rule TTP_XOR_QUAD_CurrentVersionRun_14af {
  strings:
    $key_14af = { 47 c0 [2] 63 ce [2] 48 e2 [2] 66 c0 [2] 72 db [2] 7d c1 [2] 63 dc [2] 61 dd [2] 7a db [2] 66 dc [2] 7a f3 }

  condition:
    any of them
}