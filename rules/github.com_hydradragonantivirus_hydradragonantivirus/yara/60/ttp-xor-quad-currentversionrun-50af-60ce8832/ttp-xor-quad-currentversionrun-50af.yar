rule TTP_XOR_QUAD_CurrentVersionRun_50af {
  strings:
    $key_50af = { 03 c0 [2] 27 ce [2] 0c e2 [2] 22 c0 [2] 36 db [2] 39 c1 [2] 27 dc [2] 25 dd [2] 3e db [2] 22 dc [2] 3e f3 }

  condition:
    any of them
}