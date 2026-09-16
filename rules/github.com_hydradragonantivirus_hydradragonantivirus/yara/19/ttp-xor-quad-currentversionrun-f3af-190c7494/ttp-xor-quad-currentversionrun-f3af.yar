rule TTP_XOR_QUAD_CurrentVersionRun_f3af {
  strings:
    $key_f3af = { a0 c0 [2] 84 ce [2] af e2 [2] 81 c0 [2] 95 db [2] 9a c1 [2] 84 dc [2] 86 dd [2] 9d db [2] 81 dc [2] 9d f3 }

  condition:
    any of them
}