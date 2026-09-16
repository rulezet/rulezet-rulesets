rule TTP_XOR_QUAD_CurrentVersionRun_05af {
  strings:
    $key_05af = { 56 c0 [2] 72 ce [2] 59 e2 [2] 77 c0 [2] 63 db [2] 6c c1 [2] 72 dc [2] 70 dd [2] 6b db [2] 77 dc [2] 6b f3 }

  condition:
    any of them
}