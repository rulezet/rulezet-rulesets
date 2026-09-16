rule TTP_XOR_QUAD_CurrentVersionRun_2cbc {
  strings:
    $key_2cbc = { 7f d3 [2] 5b dd [2] 70 f1 [2] 5e d3 [2] 4a c8 [2] 45 d2 [2] 5b cf [2] 59 ce [2] 42 c8 [2] 5e cf [2] 42 e0 }

  condition:
    any of them
}