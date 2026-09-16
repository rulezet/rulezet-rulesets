rule TTP_XOR_QUAD_CurrentVersionRun_40af {
  strings:
    $key_40af = { 13 c0 [2] 37 ce [2] 1c e2 [2] 32 c0 [2] 26 db [2] 29 c1 [2] 37 dc [2] 35 dd [2] 2e db [2] 32 dc [2] 2e f3 }

  condition:
    any of them
}