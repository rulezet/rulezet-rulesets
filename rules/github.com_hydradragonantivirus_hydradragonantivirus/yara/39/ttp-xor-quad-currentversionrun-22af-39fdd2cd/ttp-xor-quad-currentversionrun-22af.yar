rule TTP_XOR_QUAD_CurrentVersionRun_22af {
  strings:
    $key_22af = { 71 c0 [2] 55 ce [2] 7e e2 [2] 50 c0 [2] 44 db [2] 4b c1 [2] 55 dc [2] 57 dd [2] 4c db [2] 50 dc [2] 4c f3 }

  condition:
    any of them
}