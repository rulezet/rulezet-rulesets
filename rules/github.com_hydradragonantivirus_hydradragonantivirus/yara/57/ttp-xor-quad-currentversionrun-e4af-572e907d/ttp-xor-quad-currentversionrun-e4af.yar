rule TTP_XOR_QUAD_CurrentVersionRun_e4af {
  strings:
    $key_e4af = { b7 c0 [2] 93 ce [2] b8 e2 [2] 96 c0 [2] 82 db [2] 8d c1 [2] 93 dc [2] 91 dd [2] 8a db [2] 96 dc [2] 8a f3 }

  condition:
    any of them
}