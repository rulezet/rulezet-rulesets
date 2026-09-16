rule TTP_XOR_QUAD_CurrentVersionRun_34af {
  strings:
    $key_34af = { 67 c0 [2] 43 ce [2] 68 e2 [2] 46 c0 [2] 52 db [2] 5d c1 [2] 43 dc [2] 41 dd [2] 5a db [2] 46 dc [2] 5a f3 }

  condition:
    any of them
}