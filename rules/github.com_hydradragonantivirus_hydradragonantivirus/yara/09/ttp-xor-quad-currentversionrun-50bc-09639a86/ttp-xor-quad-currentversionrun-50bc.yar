rule TTP_XOR_QUAD_CurrentVersionRun_50bc {
  strings:
    $key_50bc = { 03 d3 [2] 27 dd [2] 0c f1 [2] 22 d3 [2] 36 c8 [2] 39 d2 [2] 27 cf [2] 25 ce [2] 3e c8 [2] 22 cf [2] 3e e0 }

  condition:
    any of them
}