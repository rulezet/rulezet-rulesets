rule TTP_XOR_QUAD_CurrentVersionRun_3cbc {
  strings:
    $key_3cbc = { 6f d3 [2] 4b dd [2] 60 f1 [2] 4e d3 [2] 5a c8 [2] 55 d2 [2] 4b cf [2] 49 ce [2] 52 c8 [2] 4e cf [2] 52 e0 }

  condition:
    any of them
}