rule TTP_XOR_QUAD_CurrentVersionRun_37af {
  strings:
    $key_37af = { 64 c0 [2] 40 ce [2] 6b e2 [2] 45 c0 [2] 51 db [2] 5e c1 [2] 40 dc [2] 42 dd [2] 59 db [2] 45 dc [2] 59 f3 }

  condition:
    any of them
}