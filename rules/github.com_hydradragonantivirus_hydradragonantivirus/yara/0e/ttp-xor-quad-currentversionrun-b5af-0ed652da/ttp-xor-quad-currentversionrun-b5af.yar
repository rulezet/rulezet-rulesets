rule TTP_XOR_QUAD_CurrentVersionRun_b5af {
  strings:
    $key_b5af = { e6 c0 [2] c2 ce [2] e9 e2 [2] c7 c0 [2] d3 db [2] dc c1 [2] c2 dc [2] c0 dd [2] db db [2] c7 dc [2] db f3 }

  condition:
    any of them
}