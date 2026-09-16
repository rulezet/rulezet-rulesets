rule TTP_XOR_QUAD_CurrentVersionRun_f6af {
  strings:
    $key_f6af = { a5 c0 [2] 81 ce [2] aa e2 [2] 84 c0 [2] 90 db [2] 9f c1 [2] 81 dc [2] 83 dd [2] 98 db [2] 84 dc [2] 98 f3 }

  condition:
    any of them
}