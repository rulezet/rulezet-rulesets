rule TTP_XOR_QUAD_CurrentVersionRun_e7af {
  strings:
    $key_e7af = { b4 c0 [2] 90 ce [2] bb e2 [2] 95 c0 [2] 81 db [2] 8e c1 [2] 90 dc [2] 92 dd [2] 89 db [2] 95 dc [2] 89 f3 }

  condition:
    any of them
}