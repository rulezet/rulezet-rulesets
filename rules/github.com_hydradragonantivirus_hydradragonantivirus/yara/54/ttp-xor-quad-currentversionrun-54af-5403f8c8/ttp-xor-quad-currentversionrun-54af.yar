rule TTP_XOR_QUAD_CurrentVersionRun_54af {
  strings:
    $key_54af = { 07 c0 [2] 23 ce [2] 08 e2 [2] 26 c0 [2] 32 db [2] 3d c1 [2] 23 dc [2] 21 dd [2] 3a db [2] 26 dc [2] 3a f3 }

  condition:
    any of them
}