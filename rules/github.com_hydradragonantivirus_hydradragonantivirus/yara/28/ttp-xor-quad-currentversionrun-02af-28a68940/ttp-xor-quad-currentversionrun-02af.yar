rule TTP_XOR_QUAD_CurrentVersionRun_02af {
  strings:
    $key_02af = { 51 c0 [2] 75 ce [2] 5e e2 [2] 70 c0 [2] 64 db [2] 6b c1 [2] 75 dc [2] 77 dd [2] 6c db [2] 70 dc [2] 6c f3 }

  condition:
    any of them
}