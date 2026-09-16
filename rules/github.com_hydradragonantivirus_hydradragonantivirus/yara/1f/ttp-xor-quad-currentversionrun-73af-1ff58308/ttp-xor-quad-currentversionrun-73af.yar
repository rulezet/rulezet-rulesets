rule TTP_XOR_QUAD_CurrentVersionRun_73af {
  strings:
    $key_73af = { 20 c0 [2] 04 ce [2] 2f e2 [2] 01 c0 [2] 15 db [2] 1a c1 [2] 04 dc [2] 06 dd [2] 1d db [2] 01 dc [2] 1d f3 }

  condition:
    any of them
}