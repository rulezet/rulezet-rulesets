rule TTP_XOR_QUAD_CurrentVersionRun_f4af {
  strings:
    $key_f4af = { a7 c0 [2] 83 ce [2] a8 e2 [2] 86 c0 [2] 92 db [2] 9d c1 [2] 83 dc [2] 81 dd [2] 9a db [2] 86 dc [2] 9a f3 }

  condition:
    any of them
}