rule TTP_XOR_QUAD_CurrentVersionRun_b1af {
  strings:
    $key_b1af = { e2 c0 [2] c6 ce [2] ed e2 [2] c3 c0 [2] d7 db [2] d8 c1 [2] c6 dc [2] c4 dd [2] df db [2] c3 dc [2] df f3 }

  condition:
    any of them
}