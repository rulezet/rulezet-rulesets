rule TTP_XOR_QUAD_CurrentVersionRun_fcbc {
  strings:
    $key_fcbc = { af d3 [2] 8b dd [2] a0 f1 [2] 8e d3 [2] 9a c8 [2] 95 d2 [2] 8b cf [2] 89 ce [2] 92 c8 [2] 8e cf [2] 92 e0 }

  condition:
    any of them
}