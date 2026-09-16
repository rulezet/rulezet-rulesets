rule TTP_XOR_QUAD_CurrentVersionRun_a7af {
  strings:
    $key_a7af = { f4 c0 [2] d0 ce [2] fb e2 [2] d5 c0 [2] c1 db [2] ce c1 [2] d0 dc [2] d2 dd [2] c9 db [2] d5 dc [2] c9 f3 }

  condition:
    any of them
}