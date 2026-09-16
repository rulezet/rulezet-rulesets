rule TTP_XOR_QUAD_CurrentVersionRun_4cbc {
  strings:
    $key_4cbc = { 1f d3 [2] 3b dd [2] 10 f1 [2] 3e d3 [2] 2a c8 [2] 25 d2 [2] 3b cf [2] 39 ce [2] 22 c8 [2] 3e cf [2] 22 e0 }

  condition:
    any of them
}