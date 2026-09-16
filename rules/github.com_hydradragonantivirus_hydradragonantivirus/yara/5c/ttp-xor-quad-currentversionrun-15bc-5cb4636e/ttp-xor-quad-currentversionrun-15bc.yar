rule TTP_XOR_QUAD_CurrentVersionRun_15bc {
  strings:
    $key_15bc = { 46 d3 [2] 62 dd [2] 49 f1 [2] 67 d3 [2] 73 c8 [2] 7c d2 [2] 62 cf [2] 60 ce [2] 7b c8 [2] 67 cf [2] 7b e0 }

  condition:
    any of them
}