rule TTP_XOR_QUAD_CurrentVersionRun_a3af {
  strings:
    $key_a3af = { f0 c0 [2] d4 ce [2] ff e2 [2] d1 c0 [2] c5 db [2] ca c1 [2] d4 dc [2] d6 dd [2] cd db [2] d1 dc [2] cd f3 }

  condition:
    any of them
}