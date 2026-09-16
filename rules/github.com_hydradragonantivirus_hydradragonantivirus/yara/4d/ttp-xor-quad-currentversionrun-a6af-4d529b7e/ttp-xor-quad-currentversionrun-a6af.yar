rule TTP_XOR_QUAD_CurrentVersionRun_a6af {
  strings:
    $key_a6af = { f5 c0 [2] d1 ce [2] fa e2 [2] d4 c0 [2] c0 db [2] cf c1 [2] d1 dc [2] d3 dd [2] c8 db [2] d4 dc [2] c8 f3 }

  condition:
    any of them
}