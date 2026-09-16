rule TTP_XOR_QUAD_CurrentVersionRun_f3bc {
  strings:
    $key_f3bc = { a0 d3 [2] 84 dd [2] af f1 [2] 81 d3 [2] 95 c8 [2] 9a d2 [2] 84 cf [2] 86 ce [2] 9d c8 [2] 81 cf [2] 9d e0 }

  condition:
    any of them
}