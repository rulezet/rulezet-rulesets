rule TTP_XOR_QUAD_CurrentVersionRun_70bc {
  strings:
    $key_70bc = { 23 d3 [2] 07 dd [2] 2c f1 [2] 02 d3 [2] 16 c8 [2] 19 d2 [2] 07 cf [2] 05 ce [2] 1e c8 [2] 02 cf [2] 1e e0 }

  condition:
    any of them
}