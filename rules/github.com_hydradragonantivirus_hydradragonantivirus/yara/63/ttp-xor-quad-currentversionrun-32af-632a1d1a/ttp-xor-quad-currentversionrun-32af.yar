rule TTP_XOR_QUAD_CurrentVersionRun_32af {
  strings:
    $key_32af = { 61 c0 [2] 45 ce [2] 6e e2 [2] 40 c0 [2] 54 db [2] 5b c1 [2] 45 dc [2] 47 dd [2] 5c db [2] 40 dc [2] 5c f3 }

  condition:
    any of them
}