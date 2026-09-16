rule TTP_XOR_QUAD_CurrentVersionRun_f2af {
  strings:
    $key_f2af = { a1 c0 [2] 85 ce [2] ae e2 [2] 80 c0 [2] 94 db [2] 9b c1 [2] 85 dc [2] 87 dd [2] 9c db [2] 80 dc [2] 9c f3 }

  condition:
    any of them
}