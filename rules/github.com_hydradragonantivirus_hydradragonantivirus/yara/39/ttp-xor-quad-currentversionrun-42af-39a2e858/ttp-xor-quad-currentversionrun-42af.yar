rule TTP_XOR_QUAD_CurrentVersionRun_42af {
  strings:
    $key_42af = { 11 c0 [2] 35 ce [2] 1e e2 [2] 30 c0 [2] 24 db [2] 2b c1 [2] 35 dc [2] 37 dd [2] 2c db [2] 30 dc [2] 2c f3 }

  condition:
    any of them
}