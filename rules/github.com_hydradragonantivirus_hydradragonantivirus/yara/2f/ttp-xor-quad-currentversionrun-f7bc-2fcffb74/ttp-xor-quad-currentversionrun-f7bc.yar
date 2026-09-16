rule TTP_XOR_QUAD_CurrentVersionRun_f7bc {
  strings:
    $key_f7bc = { a4 d3 [2] 80 dd [2] ab f1 [2] 85 d3 [2] 91 c8 [2] 9e d2 [2] 80 cf [2] 82 ce [2] 99 c8 [2] 85 cf [2] 99 e0 }

  condition:
    any of them
}