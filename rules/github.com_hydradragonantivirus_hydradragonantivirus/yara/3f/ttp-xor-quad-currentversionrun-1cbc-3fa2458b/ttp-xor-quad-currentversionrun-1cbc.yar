rule TTP_XOR_QUAD_CurrentVersionRun_1cbc {
  strings:
    $key_1cbc = { 4f d3 [2] 6b dd [2] 40 f1 [2] 6e d3 [2] 7a c8 [2] 75 d2 [2] 6b cf [2] 69 ce [2] 72 c8 [2] 6e cf [2] 72 e0 }

  condition:
    any of them
}