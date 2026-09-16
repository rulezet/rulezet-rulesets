rule TTP_XOR_QUAD_CurrentVersionRun_72af {
  strings:
    $key_72af = { 21 c0 [2] 05 ce [2] 2e e2 [2] 00 c0 [2] 14 db [2] 1b c1 [2] 05 dc [2] 07 dd [2] 1c db [2] 00 dc [2] 1c f3 }

  condition:
    any of them
}