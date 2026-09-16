rule TTP_XOR_QUAD_CurrentVersionRun_e7bc {
  strings:
    $key_e7bc = { b4 d3 [2] 90 dd [2] bb f1 [2] 95 d3 [2] 81 c8 [2] 8e d2 [2] 90 cf [2] 92 ce [2] 89 c8 [2] 95 cf [2] 89 e0 }

  condition:
    any of them
}