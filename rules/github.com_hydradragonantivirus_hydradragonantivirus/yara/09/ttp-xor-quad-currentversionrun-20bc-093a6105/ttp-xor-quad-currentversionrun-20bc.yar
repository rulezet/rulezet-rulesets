rule TTP_XOR_QUAD_CurrentVersionRun_20bc {
  strings:
    $key_20bc = { 73 d3 [2] 57 dd [2] 7c f1 [2] 52 d3 [2] 46 c8 [2] 49 d2 [2] 57 cf [2] 55 ce [2] 4e c8 [2] 52 cf [2] 4e e0 }

  condition:
    any of them
}