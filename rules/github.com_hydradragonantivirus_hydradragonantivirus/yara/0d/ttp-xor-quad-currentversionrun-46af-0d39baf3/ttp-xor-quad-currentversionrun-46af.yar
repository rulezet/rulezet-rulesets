rule TTP_XOR_QUAD_CurrentVersionRun_46af {
  strings:
    $key_46af = { 15 c0 [2] 31 ce [2] 1a e2 [2] 34 c0 [2] 20 db [2] 2f c1 [2] 31 dc [2] 33 dd [2] 28 db [2] 34 dc [2] 28 f3 }

  condition:
    any of them
}